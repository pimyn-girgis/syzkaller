// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

// reproRunner is used to run reproducers on the base kernel to determine whether it is affected.
type reproRunner struct {
	done    chan reproRunnerResult
	running atomic.Int64
}

type reproRunnerResult struct {
	reproReport *report.Report
	crashReport *report.Report
	repro       *repro.Result
	fullRepro   bool // whether this was a full reproduction
}

const (
	// We want to avoid false positives as much as possible, so let's use
	// a stricter relibability cut-off than what's used inside pkg/repro.
	reliabilityCutOff = 0.4
	// 80% reliability x 3 runs is a 0.8% chance of false positives.
	// 6 runs at 40% reproducibility gives a ~4% false positive chance.
	reliabilityThreshold = 0.8
)

// Run executes the reproducer 3 times with slightly different options.
// The objective is to verify whether the bug triggered by the reproducer affects the base kernel.
// To avoid reporting false positives, the function does not require the kernel to crash with exactly
// the same crash title as in the original crash report. Any single crash is accepted.
// The result is sent back over the rr.done channel.
func (rr *reproRunner) Run(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool) {
	if r.Reliability < reliabilityCutOff {
		log.Logf(1, "%s: repro is too unreliable, skipping", r.Report.Title)
		return
	}
	needRuns := 3
	if r.Reliability < reliabilityThreshold {
		needRuns = 6
	}

	pool := k.Pool()
	parallelism := min(needRuns, max(1, pool.Total()-1))
	reserved := int(rr.running.Add(int64(parallelism)))
	pool.ReserveForRun(min(reserved, pool.Total()))
	defer func() {
		reserved := int(rr.running.Add(-int64(parallelism)))
		pool.ReserveForRun(min(reserved, pool.Total()))
	}()

	baseDur := max(r.Duration*2, 30*time.Second)
	if fullRepro {
		baseDur = max(r.Duration, time.Minute)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	progData := r.Prog.Serialize()
	var (
		mu          sync.Mutex
		crashReport *report.Report
		aborted     bool
	)
	slots := make(chan int, needRuns)
	for slot := range needRuns {
		slots <- slot
	}
	close(slots)

	var wg sync.WaitGroup
	for range parallelism {
		wg.Go(func() {
			for slot := range slots {
				rep, ok := runSlotOnBase(runCtx, k, r, progData, baseDur, slot)
				if rep != nil {
					mu.Lock()
					if crashReport == nil {
						crashReport = rep
					}
					mu.Unlock()
					cancel()
					return
				}
				if !ok {
					if ctx.Err() == nil && runCtx.Err() == nil {
						mu.Lock()
						aborted = true
						mu.Unlock()
						cancel()
					}
					return
				}
			}
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	if aborted && crashReport == nil {
		log.Logf(0, "%s: aborting base verification after repeated VM errors", r.Report.Title)
		return
	}
	ret := reproRunnerResult{
		reproReport: r.Report,
		crashReport: crashReport,
		repro:       r,
		fullRepro:   fullRepro,
	}
	select {
	case rr.done <- ret:
	case <-ctx.Done():
	}
}

func runSlotOnBase(ctx context.Context, k Kernel, r *repro.Result,
	progData []byte, baseDur time.Duration, slot int) (*report.Report, bool) {
	opts := r.Opts
	opts.Repeat = true
	if slot%3 != 2 {
		// Two times out of 3, test with Threaded=true.
		// The third time we leave it as it was in the reproducer (in case it was important).
		opts.Threaded = true
	}
	pool := k.Pool()
	const maxAttemptsPerSlot = 5
	for range maxAttemptsPerSlot {
		if ctx.Err() != nil {
			return nil, false
		}
		var err error
		var result *instance.RunResult
		runErr := pool.Run(ctx, func(ctx context.Context, inst *vm.Instance,
			updInfo dispatcher.UpdateInfo) {
			execInst, setupErr := instance.SetupExecProg(inst, k.Config(), k.Reporter(),
				&instance.OptionalConfig{Context: ctx})
			if setupErr != nil {
				err = setupErr
				return
			}
			result, err = execInst.RunSyzProg(progData, instance.RunOptions{
				Duration: baseDur,
				Opts:     opts,
			})
		})
		logPrefix := fmt.Sprintf("attempt #%d to run %q on base", slot, r.Report.Title)
		if ctx.Err() != nil {
			log.Logf(1, "%s: aborting due to context cancelation", logPrefix)
			return nil, false
		}
		if runErr != nil || err != nil {
			log.Logf(1, "%s: skipping due to errors: %v / %v", logPrefix, runErr, err)
			continue
		}
		if result != nil && result.Report != nil {
			log.Logf(1, "%s: crashed with %s", logPrefix, result.Report.Title)
			return result.Report, true
		}
		log.Logf(1, "%s: did not crash", logPrefix)
		return nil, true
	}
	return nil, false
}

type runner interface {
	Run(ctx context.Context, k Kernel, r *repro.Result, fullRepro bool)
	Results() <-chan reproRunnerResult
}

func (rr *reproRunner) Results() <-chan reproRunnerResult {
	return rr.done
}
