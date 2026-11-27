// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExactMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
		ok      bool
	}{
		{pattern: "^ext4_iget$", want: "ext4_iget", ok: true},
		{pattern: `^fs/ext4/inode\.c$`, want: "fs/ext4/inode.c", ok: true},
		{pattern: `^func\$1$`, want: "func$1", ok: true},
		{pattern: `^func\\$`, want: `func\`, ok: true},
		{pattern: `^func\$`, want: "", ok: false},
		{pattern: "ext4_iget", want: "", ok: false},
		{pattern: "^ext4_.*$", want: "", ok: false},
		{pattern: `^\w+$`, want: "", ok: false},
		{pattern: "^(a|b)$", want: "", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			got, ok := exactMatchPattern(tc.pattern)
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestBaseSymbolNameAndHotUnits(t *testing.T) {
	assert.Equal(t, "ext4_iget", BaseSymbolName("ext4_iget"))
	assert.Equal(t, "ext4_iget", BaseSymbolName("ext4_iget.cold"))
	assert.Equal(t, "ext4_iget", BaseSymbolName("ext4_iget.isra.0.constprop.1"))
	assert.True(t, IsHotCoreKernelUnit("mm/slub.c"))
	assert.True(t, IsHotCoreKernelUnit("kernel/sched/fair.c"))
	assert.False(t, IsHotCoreKernelUnit("fs/ext4/inode.c"))
	assert.False(t, IsHotCoreKernelUnit("net/ipv6/route.c"))
}

func TestCovFilterAddFilterExactAndStrict(t *testing.T) {
	units := []*backend.ObjectUnit{
		{Name: "sym_a", PCs: []uint64{0x10}},
		{Name: "sym_b", PCs: []uint64{0x20}, CMPs: []uint64{0x24}},
		{Name: "prefix_c", PCs: []uint64{0x30}},
	}
	foreach := func(apply func(*backend.ObjectUnit)) {
		for _, u := range units {
			apply(u)
		}
	}

	pcs := make(map[uint64]struct{})
	err := covFilterAddFilter(pcs, []string{"^sym_a$", "^prefix_.*$"}, foreach, true)
	require.NoError(t, err)
	assert.Equal(t, map[uint64]struct{}{0x10: {}, 0x30: {}}, pcs)

	err = covFilterAddFilter(make(map[uint64]struct{}), []string{"^missing$"}, foreach, true)
	require.Error(t, err)
}

func TestPrepareCoverageFiltersSharded(t *testing.T) {
	sysTarget := targets.Get(targets.Linux, targets.AMD64)
	require.NotNil(t, sysTarget)

	nextPC := func(pc uint64) uint64 {
		return backend.NextInstructionPC(sysTarget, "qemu", pc)
	}

	ext4Unit := &backend.CompileUnit{
		ObjectUnit: backend.ObjectUnit{Name: "fs/ext4/inode.c", PCs: []uint64{0x100, 0x110, 0x120}},
	}
	ext4SuperUnit := &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{Name: "fs/ext4/super.c", PCs: []uint64{0x200}}}
	slubUnit := &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{Name: "mm/slub.c", PCs: []uint64{0x300, 0x310}}}
	otherUnit1 := &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{Name: "net/ipv4/tcp.c", PCs: []uint64{0x400}}}
	otherUnit2 := &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{Name: "net/ipv6/tcp_ipv6.c", PCs: []uint64{0x500}}}

	impl := &backend.Impl{
		Units: []*backend.CompileUnit{ext4Unit, ext4SuperUnit, slubUnit, otherUnit1, otherUnit2},
		Symbols: []*backend.Symbol{
			// Directly matched hunk function + .cold split + inlined static caller in same unit.
			{Unit: ext4Unit, ObjectUnit: backend.ObjectUnit{Name: "ext4_iget", PCs: []uint64{0x100}}},
			{Unit: ext4Unit, ObjectUnit: backend.ObjectUnit{Name: "ext4_iget.cold", PCs: []uint64{0x108}}},
			{Unit: ext4Unit, ObjectUnit: backend.ObjectUnit{Name: "ext4_writepages", PCs: []uint64{0x110}}},
			{Unit: ext4Unit, ObjectUnit: backend.ObjectUnit{Name: "ext4_untouched", PCs: []uint64{0x120}}},
			// Cross-unit static inline appearing in 3 units: must NOT be treated as unique changed symbol.
			{Unit: ext4Unit, ObjectUnit: backend.ObjectUnit{Name: "common_inline", PCs: []uint64{0x130}}},
			{Unit: otherUnit1, ObjectUnit: backend.ObjectUnit{Name: "common_inline", PCs: []uint64{0x430}}},
			{Unit: otherUnit2, ObjectUnit: backend.ObjectUnit{Name: "common_inline", PCs: []uint64{0x530}}},
			// Unmodified caller unit in same subdir affected by header inline change.
			{Unit: ext4SuperUnit, ObjectUnit: backend.ObjectUnit{Name: "ext4_fill_super", PCs: []uint64{0x200}}},
			// Hot core unit: if hunk function doesn't match and no unique changed symbols, must NOT fall back to whole unit.
			{Unit: slubUnit, ObjectUnit: backend.ObjectUnit{Name: "kmem_cache_alloc", PCs: []uint64{0x300}}},
		},
	}

	wrapper := &ReportGeneratorWrapper{
		initialized: true,
		cached:      &cover.ReportGenerator{Impl: impl},
	}
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{SysTarget: sysTarget},
		Type:    "qemu",
		Experimental: mgrconfig.Experimental{
			ModifiedFiles:   []string{"fs/ext4/inode.c", "fs/ext4/ext4.h", "mm/slub.c"},
			ModifiedSymbols: []string{"ext4_iget", "ext4_writepages", "common_inline", "ext4_fill_super"},
			FocusAreas: []mgrconfig.FocusArea{
				{
					Name: "fs/ext4/inode.c",
					Filter: mgrconfig.CovFilterCfg{
						Unit:      "fs/ext4/inode.c",
						Functions: []string{"ext4_iget"},
					},
					Weight:         8.0,
					AdaptiveWeight: true,
				},
				{
					Name: "mm/slub.c",
					Filter: mgrconfig.CovFilterCfg{
						Unit:      "mm/slub.c",
						Functions: []string{"inlined_slub_helper"},
					},
					Weight:         8.0,
					AdaptiveWeight: true,
				},
				{
					Name: "header_inlines",
					Filter: mgrconfig.CovFilterCfg{
						IncludeHeaderInlines: true,
					},
					Weight:         4.0,
					AdaptiveWeight: true,
				},
			},
		},
	}

	res, err := PrepareCoverageFilters(wrapper, cfg, false)
	require.NoError(t, err)
	require.Len(t, res.Areas, 2)

	assert.Equal(t, "fs/ext4/inode.c", res.Areas[0].Name)
	assert.True(t, res.Areas[0].AdaptiveWeight)
	assert.Equal(t, map[uint64]struct{}{
		nextPC(0x100): {},
		nextPC(0x108): {},
		nextPC(0x110): {},
	}, res.Areas[0].CoverPCs)

	assert.Equal(t, "header_inlines", res.Areas[1].Name)
	assert.Equal(t, map[uint64]struct{}{
		nextPC(0x200): {},
	}, res.Areas[1].CoverPCs)

	assert.Equal(t, map[uint64]struct{}{
		nextPC(0x100): {},
		nextPC(0x108): {},
		nextPC(0x110): {},
		nextPC(0x200): {},
	}, res.ExecutorFilter)
}

func TestPrepareCoverageFiltersLineShiftCap(t *testing.T) {
	sysTarget := targets.Get(targets.Linux, targets.AMD64)
	require.NotNil(t, sysTarget)

	unit := &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{Name: "drivers/net/foo.c"}}
	var syms []*backend.Symbol
	var modifiedSyms []string
	// 12 changed symbols in the unit due to __LINE__ shifts, plus 1 hunk function.
	for i := range 12 {
		name := fmt.Sprintf("bystander_%d", i)
		pc := uint64(0x1000 + i*0x10)
		unit.PCs = append(unit.PCs, pc)
		syms = append(syms, &backend.Symbol{
			Unit:       unit,
			ObjectUnit: backend.ObjectUnit{Name: name, PCs: []uint64{pc}},
		})
		modifiedSyms = append(modifiedSyms, name)
	}
	syms = append(syms, &backend.Symbol{
		Unit:       unit,
		ObjectUnit: backend.ObjectUnit{Name: "patched_fn", PCs: []uint64{0x2000}},
	})
	modifiedSyms = append(modifiedSyms, "patched_fn")

	wrapper := &ReportGeneratorWrapper{
		initialized: true,
		cached:      &cover.ReportGenerator{Impl: &backend.Impl{Units: []*backend.CompileUnit{unit}, Symbols: syms}},
	}
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{SysTarget: sysTarget},
		Type:    "qemu",
		Experimental: mgrconfig.Experimental{
			ModifiedFiles:   []string{"drivers/net/foo.c"},
			ModifiedSymbols: modifiedSyms,
			FocusAreas: []mgrconfig.FocusArea{
				{
					Name: "drivers/net/foo.c",
					Filter: mgrconfig.CovFilterCfg{
						Unit:      "drivers/net/foo.c",
						Functions: []string{"patched_fn"},
					},
					Weight: 8.0,
				},
			},
		},
	}

	res, err := PrepareCoverageFilters(wrapper, cfg, false)
	require.NoError(t, err)
	require.Len(t, res.Areas, 1)
	assert.Equal(t, map[uint64]struct{}{
		backend.NextInstructionPC(sysTarget, "qemu", 0x2000): {},
	}, res.Areas[0].CoverPCs)
}

func TestPrepareCoverageFiltersFallbackWhenAllEmpty(t *testing.T) {
	sysTarget := targets.Get(targets.Linux, targets.AMD64)
	require.NotNil(t, sysTarget)

	wrapper := &ReportGeneratorWrapper{
		initialized: true,
		cached:      &cover.ReportGenerator{Impl: &backend.Impl{}},
	}
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{SysTarget: sysTarget},
		Type:    "qemu",
		Experimental: mgrconfig.Experimental{
			FocusAreas: []mgrconfig.FocusArea{
				{
					Name:   "drivers/unbuilt/foo.c",
					Filter: mgrconfig.CovFilterCfg{Unit: "drivers/unbuilt/foo.c"},
					Weight: 8.0,
				},
			},
		},
	}

	res, err := PrepareCoverageFilters(wrapper, cfg, false)
	require.NoError(t, err)
	require.Len(t, res.Areas, 1)
	assert.Empty(t, res.Areas[0].CoverPCs)
	assert.Nil(t, res.ExecutorFilter)

	_, err = PrepareCoverageFilters(wrapper, cfg, true)
	require.Error(t, err)
}
