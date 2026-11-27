// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package corpus manages syzkaller test program corpora, signal tracking, and corpus minimization.
package corpus

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// Corpus object represents a set of syzkaller-found programs that
// cover the kernel up to the currently reached frontiers.
type Corpus struct {
	ctx      context.Context
	mu       sync.RWMutex
	progsMap map[string]*Item
	signal   signal.Signal // total signal of all items
	cover    cover.Cover   // total coverage of all items
	updates  chan<- NewItemEvent

	*ProgramsList
	StatProgs  *stat.Val
	StatSignal *stat.Val
	StatCover  *stat.Val

	focusAreas []*focusAreaState
	pcToAreas  map[uint64][]*focusAreaState
}

type focusAreaState struct {
	FocusArea
	*ProgramsList
	smashed int
}

type FocusArea struct {
	Name           string // can be empty
	CoverPCs       map[uint64]struct{}
	Weight         float64
	AdaptiveWeight bool
}

func (fa *FocusArea) inAreaPCs(cover []uint64) int {
	var count int
	for _, pc := range cover {
		if _, ok := fa.CoverPCs[pc]; ok {
			count++
		}
	}
	return count
}

func NewCorpus(ctx context.Context) *Corpus {
	return NewMonitoredCorpus(ctx, nil)
}

func NewMonitoredCorpus(ctx context.Context, updates chan<- NewItemEvent) *Corpus {
	return NewFocusedCorpus(ctx, updates, nil)
}

func NewFocusedCorpus(ctx context.Context, updates chan<- NewItemEvent, areas []FocusArea) *Corpus {
	corpus := &Corpus{
		ctx:          ctx,
		progsMap:     make(map[string]*Item),
		updates:      updates,
		ProgramsList: &ProgramsList{},
	}
	corpus.StatProgs = stat.New("corpus", "Number of test programs in the corpus", stat.Console,
		stat.Link("/corpus"), stat.Graph("corpus"), stat.LenOf(&corpus.progsMap, &corpus.mu))
	corpus.StatSignal = stat.New("signal", "Fuzzing signal in the corpus",
		stat.LenOf(&corpus.signal, &corpus.mu))
	corpus.StatCover = stat.New("coverage", "Source coverage in the corpus", stat.Console,
		stat.Link("/cover"), stat.Prometheus("syz_corpus_cover"), stat.LenOf(&corpus.cover, &corpus.mu))
	const maxConsoleAreaStats = 16
	for _, area := range areas {
		obj := &ProgramsList{}
		if len(area.CoverPCs) == 0 {
			obj = corpus.ProgramsList
		} else if len(areas) > 1 && len(areas) <= maxConsoleAreaStats && area.Name != "" {
			// Only show individual statistics when there is a small number of areas.
			stat.New("corpus ["+area.Name+"]",
				fmt.Sprintf("Corpus programs of the focus area %q", area.Name),
				stat.Console, stat.Graph("corpus"),
				stat.LenOf(&obj.progs, &corpus.mu))
		}
		state := &focusAreaState{
			FocusArea:    area,
			ProgramsList: obj,
		}
		corpus.focusAreas = append(corpus.focusAreas, state)
		if len(area.CoverPCs) > 0 {
			if corpus.pcToAreas == nil {
				corpus.pcToAreas = make(map[uint64][]*focusAreaState)
			}
			for pc := range area.CoverPCs {
				corpus.pcToAreas[pc] = append(corpus.pcToAreas[pc], state)
			}
		}
	}
	if len(areas) > maxConsoleAreaStats {
		stat.New("focused areas", "Number of focus areas reached by corpus programs", stat.Console,
			func() int {
				corpus.mu.RLock()
				defer corpus.mu.RUnlock()
				reached := 0
				for _, area := range corpus.focusAreas {
					if len(area.CoverPCs) > 0 && area.Name != "" && len(area.progs) > 0 {
						reached++
					}
				}
				return reached
			})
	}
	return corpus
}

// ItemUpdate represents an update to a corpus item.
// A single program may be relevant for multiple syscalls, resulting in multiple
// ItemUpdate entities.
type ItemUpdate struct {
	Call     int
	RawCover []uint64
}

// Item objects are to be treated as immutable, otherwise it's just
// too hard to synchonize accesses to them across the whole project.
// When Corpus updates one of its items, it saves a copy of it.
type Item struct {
	Sig        string
	Call       int
	Prog       *prog.Prog
	HasAny     bool // whether the prog contains squashed arguments
	Signal     signal.Signal
	Cover      []uint64
	FocusCover []uint64
	Updates    []ItemUpdate

	areas map[*focusAreaState]struct{}
}

func (item Item) StringCall() string {
	return item.Prog.CallName(item.Call)
}

func (item Item) focusPCs() []uint64 {
	if len(item.FocusCover) > 0 {
		return item.FocusCover
	}
	return item.Cover
}

type NewInput struct {
	Prog       *prog.Prog
	Call       int
	Signal     signal.Signal
	Cover      []uint64
	FocusCover []uint64
	RawCover   []uint64
}

type NewItemEvent struct {
	Sig      string
	Exists   bool
	ProgData []byte
	NewCover []uint64
}

func (corpus *Corpus) Save(inp NewInput) {
	progData := inp.Prog.Serialize()
	sig := hash.String(progData)

	corpus.mu.Lock()
	defer corpus.mu.Unlock()

	update := ItemUpdate{
		Call:     inp.Call,
		RawCover: inp.RawCover,
	}
	exists := false
	if old, ok := corpus.progsMap[sig]; ok {
		exists = true
		newSignal := old.Signal.Copy()
		newSignal.Merge(inp.Signal)
		var newCover cover.Cover
		newCover.Merge(old.Cover)
		newCover.Merge(inp.Cover)
		var focusCover []uint64
		if len(old.FocusCover) > 0 || len(inp.FocusCover) > 0 {
			var fc cover.Cover
			fc.Merge(old.FocusCover)
			fc.Merge(inp.Cover)
			fc.Merge(inp.FocusCover)
			focusCover = fc.Serialize()
		}
		newItem := &Item{
			Sig:        sig,
			Prog:       old.Prog,
			Call:       old.Call,
			HasAny:     old.HasAny,
			Signal:     newSignal,
			Cover:      newCover.Serialize(),
			FocusCover: focusCover,
			Updates:    slices.Clone(old.Updates),
			areas:      maps.Clone(old.areas),
		}
		const maxUpdates = 32
		if len(newItem.Updates) < maxUpdates {
			newItem.Updates = append(newItem.Updates, update)
		}
		corpus.progsMap[sig] = newItem
		corpus.applyFocusAreas(newItem)
	} else {
		var focusCover []uint64
		if len(inp.FocusCover) > 0 {
			var fc cover.Cover
			fc.Merge(inp.Cover)
			fc.Merge(inp.FocusCover)
			focusCover = fc.Serialize()
		}
		item := &Item{
			Sig:        sig,
			Call:       inp.Call,
			Prog:       inp.Prog,
			HasAny:     inp.Prog.ContainsAny(),
			Signal:     inp.Signal,
			Cover:      inp.Cover,
			FocusCover: focusCover,
			Updates:    []ItemUpdate{update},
		}
		corpus.progsMap[sig] = item
		corpus.applyFocusAreas(item)
		corpus.saveProgram(inp.Prog, len(inp.Signal))
	}
	corpus.signal.Merge(inp.Signal)
	newCover := corpus.cover.MergeDiff(inp.Cover)
	if corpus.updates != nil {
		select {
		case <-corpus.ctx.Done():
		case corpus.updates <- NewItemEvent{
			Sig:      sig,
			Exists:   exists,
			ProgData: progData,
			NewCover: newCover,
		}:
		}
	}
}

func (corpus *Corpus) applyFocusAreas(item *Item) {
	if len(corpus.pcToAreas) == 0 {
		return
	}
	var hits map[*focusAreaState]int
	for _, pc := range item.focusPCs() {
		for _, area := range corpus.pcToAreas[pc] {
			if _, ok := item.areas[area]; ok {
				continue
			}
			if hits == nil {
				hits = make(map[*focusAreaState]int)
			}
			hits[area]++
		}
	}
	if len(hits) == 0 {
		return
	}
	for _, area := range corpus.focusAreas {
		prio := hits[area]
		if prio == 0 {
			continue
		}
		area.saveProgram(item.Prog, prio)
		if item.areas == nil {
			item.areas = make(map[*focusAreaState]struct{})
		}
		item.areas[area] = struct{}{}
	}
}

const minFocusSmashWeight = 4.0

// ClaimFocusSmash checks whether coverPCs hit any high-priority focus area that has
// fewer than maxPerArea smashed inputs so far, claiming a smash slot on matched areas.
func (corpus *Corpus) ClaimFocusSmash(coverPCs []uint64, maxPerArea int) (bool, []*prog.Prog) {
	if maxPerArea <= 0 {
		return false, nil
	}
	corpus.mu.Lock()
	defer corpus.mu.Unlock()
	if len(corpus.pcToAreas) == 0 {
		return false, nil
	}
	var matched []*focusAreaState
	seen := make(map[*focusAreaState]struct{})
	for _, pc := range coverPCs {
		for _, area := range corpus.pcToAreas[pc] {
			if area.Weight < minFocusSmashWeight || area.smashed >= maxPerArea {
				continue
			}
			if _, ok := seen[area]; ok {
				continue
			}
			seen[area] = struct{}{}
			matched = append(matched, area)
		}
	}
	if len(matched) == 0 {
		return false, nil
	}
	var bestPool []*prog.Prog
	for _, area := range matched {
		area.smashed++
		if len(area.progs) > len(bestPool) {
			bestPool = area.progs
		}
	}
	return true, bestPool
}

func (corpus *Corpus) Signal() signal.Signal {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.signal.Copy()
}

func (corpus *Corpus) Items() []*Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := make([]*Item, 0, len(corpus.progsMap))
	for _, item := range corpus.progsMap {
		ret = append(ret, item)
	}
	return ret
}

func (corpus *Corpus) Item(sig string) *Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progsMap[sig]
}

type CallCov struct {
	Count int
	Cover cover.Cover
}

func (corpus *Corpus) CallCover() map[string]*CallCov {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	calls := make(map[string]*CallCov)
	for _, inp := range corpus.progsMap {
		call := inp.StringCall()
		if calls[call] == nil {
			calls[call] = new(CallCov)
		}
		cc := calls[call]
		cc.Count++
		cc.Cover.Merge(inp.Cover)
	}
	return calls
}

func (corpus *Corpus) ProgsPerArea() map[string]int {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := map[string]int{}
	for _, item := range corpus.focusAreas {
		ret[item.Name] = len(item.progs)
	}
	return ret
}

func (corpus *Corpus) Cover() []uint64 {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.cover.Serialize()
}
