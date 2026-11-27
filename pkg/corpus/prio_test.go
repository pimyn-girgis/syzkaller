// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestChooseProgram(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())

	const (
		maxIters   = 1000
		sizeCorpus = 1000
		eps        = 0.01
	)

	priorities := make(map[*prog.Prog]int64)
	for i := range sizeCorpus {
		sizeSig := i + 1
		if sizeSig%250 == 0 {
			sizeSig = 0
		}
		inp := generateInput(target, rs, sizeSig)
		corpus.Save(inp)
		priorities[inp.Prog] = int64(len(inp.Signal))
	}
	counters := make(map[*prog.Prog]int)
	for range maxIters {
		counters[corpus.chooseProgram(r)]++
	}
	for p, prio := range priorities {
		prob := float64(prio) / float64(corpus.sumPrios)
		diff := math.Abs(prob*maxIters - float64(counters[p]))
		if diff > eps*maxIters {
			t.Fatalf("the difference (%f) is higher than %f%%", diff, eps*100)
		}
	}
}

func TestFocusAreas(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			CoverPCs: map[uint64]struct{}{
				0: {},
				1: {},
			},
			Weight: 10,
		},
		{
			CoverPCs: map[uint64]struct{}{
				2: {},
				3: {},
			},
			Weight: 30,
		},
		{
			// An empty CoverPCs filter matches the whole corpus.
			Weight: 60,
		},
	})

	rs := rand.NewSource(0)

	fillGroup := func(from, to, count int) map[*prog.Prog]bool {
		ret := map[*prog.Prog]bool{}
		for i := range count {
			a := from + i%(to-from+1)
			b := a + i%(to-a+1)
			inp := generateRangedInput(target, rs, a, b)
			ret[inp.Prog] = true
			corpus.Save(inp)
		}
		return ret
	}

	first := fillGroup(0, 1, 10)
	second := fillGroup(2, 3, 10)
	third := fillGroup(4, 5, 10)

	rnd := rand.New(rs)
	different := map[*prog.Prog]bool{}
	firstCount, secondCount, thirdCount := 0, 0, 0
	const TOTAL = 10000
	for range TOTAL {
		p := corpus.ChooseProgram(rnd)
		different[p] = true

		if first[p] {
			firstCount++
		} else if second[p] {
			secondCount++
		} else if third[p] {
			thirdCount++
		}
	}

	assert.Greater(t, len(different), 25)
	// The third area (weight 60%) covers all 3 groups equally (20% each).
	assert.InDelta(t, firstCount, TOTAL*0.3, TOTAL/25)
	assert.InDelta(t, secondCount, TOTAL*0.5, TOTAL/25)
	assert.InDelta(t, thirdCount, TOTAL*0.2, TOTAL/25)
}

func TestFocusAreaInAreaWeighting(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(0)
	rnd := rand.New(rs)

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "patch",
			CoverPCs: map[uint64]struct{}{10: {}, 11: {}},
			Weight:   1.0,
		},
	})

	// inp1 has 100 global signal entries, but only 1 PC in the focus area.
	inp1 := generateRangedInput(target, rs, 1, 100)
	inp1.Cover = []uint64{10}

	// inp2 has only 2 global signal entries, but both of its PCs are in the focus area.
	inp2 := generateRangedInput(target, rs, 101, 102)
	inp2.Cover = []uint64{10, 11}

	corpus.Save(inp1)
	corpus.Save(inp2)

	verifySampling := func(stage string) {
		counts := make(map[*prog.Prog]int)
		const iters = 10000
		for range iters {
			counts[corpus.ChooseProgram(rnd)]++
		}
		// inp2 has 2 focus PCs, inp1 has 1 focus PC.
		// inp2 should be chosen ~2/3 (66.7%) of the time, inp1 ~1/3 (33.3%).
		// Under the old bug (len(signal)), inp1 would be chosen ~98% of the time.
		assert.InDelta(t, 2.0/3.0, float64(counts[inp2.Prog])/iters, 0.05, stage)
		assert.InDelta(t, 1.0/3.0, float64(counts[inp1.Prog])/iters, 0.05, stage)
	}

	verifySampling("before minimization")
	corpus.Minimize(true)
	verifySampling("after minimization")
}

func TestAdaptiveWeightAndAreaSplice(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(42)
	rnd := rand.New(rs)

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:           "flooded_area",
			CoverPCs:       map[uint64]struct{}{10: {}},
			Weight:         8.0,
			AdaptiveWeight: true,
		},
		{
			Name:           "rare_area",
			CoverPCs:       map[uint64]struct{}{20: {}},
			Weight:         8.0,
			AdaptiveWeight: true,
		},
	})

	floodedProgs := make(map[*prog.Prog]bool)
	for i := range 100 {
		inp := generateRangedInput(target, rs, i+1, i+1)
		inp.Cover = []uint64{10}
		floodedProgs[inp.Prog] = true
		corpus.Save(inp)
	}
	rareInputs := make(map[*prog.Prog]bool)
	for i := range 2 {
		inp := generateRangedInput(target, rs, 500+i, 500+i)
		inp.Cover = []uint64{20}
		rareInputs[inp.Prog] = true
		corpus.Save(inp)
	}

	rareCount := 0
	areaSpliceHits := 0
	const iters = 5000
	for range iters {
		p, splicePool := corpus.ChooseProgramWithSplice(rnd)
		if rareInputs[p] {
			rareCount++
			if len(splicePool) == 2 {
				areaSpliceHits++
			}
		}
	}
	// With AdaptiveWeight: rare_area (N=2, <=4 boost) gets weight 8*2/sqrt(2) = 11.31
	// vs flooded_area (N=100) 8/sqrt(100) = 0.8.
	// So rare_area should be selected >85% of the time despite having 50x fewer programs!
	assert.Greater(t, float64(rareCount)/iters, 0.85)
	assert.Greater(t, float64(areaSpliceHits)/float64(rareCount), 0.70)
}

func TestClaimFocusSmash(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	rs := rand.NewSource(1)

	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name:     "high_prio_patch",
			CoverPCs: map[uint64]struct{}{100: {}},
			Weight:   8.0,
		},
		{
			Name:     "low_prio_bg",
			CoverPCs: map[uint64]struct{}{200: {}},
			Weight:   1.5,
		},
	})

	inp := generateRangedInput(target, rs, 1, 1)
	inp.Cover = []uint64{100}
	corpus.Save(inp)

	ok, pool := corpus.ClaimFocusSmash([]uint64{200}, 2)
	assert.False(t, ok)
	assert.Empty(t, pool)

	ok, pool = corpus.ClaimFocusSmash([]uint64{100}, 2)
	assert.True(t, ok)
	assert.Len(t, pool, 1)

	ok, _ = corpus.ClaimFocusSmash([]uint64{100}, 2)
	assert.True(t, ok)

	// Third claim exceeds maxPerArea=2.
	ok, _ = corpus.ClaimFocusSmash([]uint64{100}, 2)
	assert.False(t, ok)
}
