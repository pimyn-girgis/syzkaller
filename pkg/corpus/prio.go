// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"math"
	"math/rand"
	"sort"

	"github.com/google/syzkaller/prog"
)

type ProgramsList struct {
	progs    []*prog.Prog
	sumPrios int64
	accPrios []int64
}

func (pl *ProgramsList) chooseProgram(r *rand.Rand) *prog.Prog {
	if len(pl.progs) == 0 {
		return nil
	}
	randVal := r.Int63n(pl.sumPrios) + 1
	idx := sort.Search(len(pl.accPrios), func(i int) bool {
		return pl.accPrios[i] >= randVal
	})
	return pl.progs[idx]
}

func (pl *ProgramsList) saveProgram(p *prog.Prog, prio int) {
	if prio == 0 {
		prio = 1
	}
	pl.sumPrios += int64(prio)
	pl.accPrios = append(pl.accPrios, pl.sumPrios)
	pl.progs = append(pl.progs, p)
}

func (fa *focusAreaState) effectiveWeight() float64 {
	if !fa.AdaptiveWeight || len(fa.progs) == 0 {
		return fa.Weight
	}
	w := fa.Weight / math.Sqrt(float64(len(fa.progs)))
	if len(fa.progs) <= 4 {
		w *= 2.0
	}
	return w
}

func (corpus *Corpus) ChooseProgram(r *rand.Rand) *prog.Prog {
	p, _ := corpus.ChooseProgramWithSplice(r)
	return p
}

// ChooseProgramWithSplice picks a corpus program according to focus area weights and returns
// both the chosen program and a pool of programs suitable for splice mutations.
func (corpus *Corpus) ChooseProgramWithSplice(r *rand.Rand) (*prog.Prog, []*prog.Prog) {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	if len(corpus.progsMap) == 0 {
		return nil, nil
	}
	var randArea *focusAreaState
	if len(corpus.focusAreas) > 0 {
		sum := 0.0
		nonEmpty := make([]*focusAreaState, 0, len(corpus.focusAreas))
		weights := make([]float64, 0, len(corpus.focusAreas))
		for _, area := range corpus.focusAreas {
			if len(area.progs) == 0 {
				continue
			}
			w := area.effectiveWeight()
			sum += w
			nonEmpty = append(nonEmpty, area)
			weights = append(weights, w)
		}
		val := r.Float64() * sum
		currSum := 0.0
		for i, area := range nonEmpty {
			if val >= currSum {
				randArea = area
			}
			currSum += weights[i]
		}
	}
	if randArea != nil {
		p := randArea.chooseProgram(r)
		if len(randArea.CoverPCs) > 0 && len(randArea.progs) >= 2 && r.Intn(5) != 0 {
			return p, randArea.progs
		}
		return p, corpus.progs
	}
	return corpus.chooseProgram(r), corpus.progs
}

func (corpus *Corpus) Programs() []*prog.Prog {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progs
}

func (pl *ProgramsList) clear() {
	pl.progs = nil
	pl.accPrios = nil
	pl.sumPrios = 0
}
