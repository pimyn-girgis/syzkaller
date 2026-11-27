// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatchFocusAreas(t *testing.T) {
	cfg := &mgrconfig.Config{}

	baseHashes, patchedHashes := dummySymbolHashes(), dummySymbolHashes()
	baseHashes["function"] = "hash1"
	patchedHashes["function"] = "hash2"

	PatchFocusAreas(cfg, [][]byte{
		[]byte(`diff --git a/b.c b/b.c
index 103167d..fbf7a68 100644
--- a/b.c
+++ b/b.c
@@ -1 +1 @@
-int main(void) { }
\ No newline at end of file
+int main(void) { return 1; }
\ No newline at end of file`),
		// Also, emulate an update to header.h.
		[]byte(`diff --git a/header.h b/header.h
index 103167d..fbf7a68 100644
--- a/header.h
+++ b/header.h
@@ -1 +1 @@
-Test
\ No newline at end of file
+Test2
\ No newline at end of file`),
	}, baseHashes, patchedHashes)

	assert.Equal(t, []mgrconfig.FocusArea{
		{
			Name: symbolsArea,
			Filter: mgrconfig.CovFilterCfg{
				Functions: []string{"^function$"},
			},
			Weight: 6.0,
		},
		{
			Name: filesArea,
			Filter: mgrconfig.CovFilterCfg{
				Files: []string{"b.c", "header.h"},
			},
			Weight: 3.0,
		},
		{
			Weight: 1.0,
		},
	}, cfg.Experimental.FocusAreas)
}

func dummySymbolHashes() map[string]string {
	ret := map[string]string{}
	for i := range 100 {
		ret[fmt.Sprint(i)] = fmt.Sprint(i)
	}
	return ret
}

func TestModifiedSymbols(t *testing.T) {
	t.Run("too many changed", func(t *testing.T) {
		ret := modifiedSymbols(map[string]string{
			"functionA": "hash1",
			"functionB": "hash2",
		}, map[string]string{
			"functionA": "hash1",
			"functionB": "hash is not hash2",
		})
		assert.Empty(t, ret)
	})
	t.Run("less than threshold", func(t *testing.T) {
		base, patched := dummySymbolHashes(), dummySymbolHashes()
		base["function"] = "hash1"
		patched["function"] = "hash2"
		base["function2"] = "hash1"
		patched["function2"] = "hash2"
		assert.Equal(t, []string{"function", "function2"}, modifiedSymbols(base, patched))
	})
}

func TestExtractTopLevelFunctions(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "single-line static function",
			line: "static int ext4_iget(struct super_block *sb, unsigned long ino)",
			want: []string{"ext4_iget"},
		},
		{
			name: "two-line kernel style function",
			line: "ext4_writepages(struct address_space *mapping, struct writeback_control *wbc)",
			want: []string{"ext4_writepages"},
		},
		{
			name: "leading attribute annotation",
			line: "__printf(2, 3) void drm_err(const struct drm_device *dev, const char *format, ...)",
			want: []string{"drm_err"},
		},
		{
			name: "syscall define",
			line: "SYSCALL_DEFINE3(io_uring_enter, unsigned int, fd, u32, to_submit, u32, min_complete)",
			want: []string{
				"__do_sys_io_uring_enter",
				"__se_sys_io_uring_enter",
				"__x64_sys_io_uring_enter",
				"__ia32_sys_io_uring_enter",
			},
		},
		{
			name: "compat syscall define",
			line: "COMPAT_SYSCALL_DEFINE2(truncate, const char __user *, path, compat_off_t, length)",
			want: []string{
				"__do_compat_sys_truncate",
				"__se_compat_sys_truncate",
				"__ia32_compat_sys_truncate",
			},
		},
		{
			name: "bpf helper call",
			line: "BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)",
			want: []string{"bpf_map_lookup_elem", "____bpf_map_lookup_elem"},
		},
		{
			name: "reject uppercase macro",
			line: "DEFINE_MUTEX(ext4_lock);",
			want: nil,
		},
		{
			name: "reject control flow",
			line: "if (unlikely(err))",
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, extractTopLevelFunctions(tc.line))
		})
	}
}

func TestPatchFocusAreasShardedLargeSeries(t *testing.T) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Linux,
			TargetArch: targets.AMD64,
			SysTarget:  targets.Get(targets.Linux, targets.AMD64),
		},
	}

	var patches [][]byte
	for i := range 16 {
		file := fmt.Sprintf("drivers/net/drv%d.c", i)
		fn := fmt.Sprintf("drv%d_rx", i)
		patches = append(patches, []byte(fmt.Sprintf(`diff --git a/%[1]s b/%[1]s
--- a/%[1]s
+++ b/%[1]s
@@ -10,4 +10,5 @@ static int %[2]s(struct sk_buff *skb)
 	return 0;
+	return 1;
`, file, fn)))
	}
	// Include a hot core unit, a header with an inline helper, a foreign-arch file, a doc file, and a deleted file.
	patches = append(patches,
		[]byte(`diff --git a/mm/slub.c b/mm/slub.c
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -100,3 +100,4 @@ void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 	return nil;
`),
		[]byte(`diff --git a/include/net/foo.h b/include/net/foo.h
--- a/include/net/foo.h
+++ b/include/net/foo.h
@@ -20,3 +20,4 @@ static inline int foo_hdr_helper(int x)
 	return x + 1;
`),
		[]byte(`diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
--- a/include/linux/memcontrol.h
+++ b/include/linux/memcontrol.h
@@ -40,3 +40,4 @@ static inline struct mem_cgroup *folio_memcg(struct folio *folio)
 	return nil;
`),
		[]byte(`diff --git a/arch/arm64/kvm/arm.c b/arch/arm64/kvm/arm.c
--- a/arch/arm64/kvm/arm.c
+++ b/arch/arm64/kvm/arm.c
@@ -10,3 +10,4 @@ int kvm_arch_init(void)
 	return 0;
`),
		[]byte(`diff --git a/Documentation/networking/foo.rst b/Documentation/networking/foo.rst
--- a/Documentation/networking/foo.rst
+++ b/Documentation/networking/foo.rst
@@ -1 +1,2 @@
+doc line
`),
		[]byte(`diff --git a/drivers/net/removed.c b/drivers/net/removed.c
deleted file mode 100644
--- a/drivers/net/removed.c
+++ /dev/null
@@ -1,3 +0,0 @@
-static int removed_fn(void) { return 0; }
`),
	)

	baseHashes := map[string]string{"drv0_rx": "h1", "unchanged": "h0"}
	patchedHashes := map[string]string{"drv0_rx": "h2", "unchanged": "h0"}

	PatchFocusAreas(cfg, patches, baseHashes, patchedHashes)

	assert.NotContains(t, cfg.Experimental.ModifiedFiles, "arch/arm64/kvm/arm.c")
	assert.NotContains(t, cfg.Experimental.ModifiedFiles, "Documentation/networking/foo.rst")
	assert.Equal(t, []string{"drv0_rx"}, cfg.Experimental.ModifiedSymbols)

	byName := make(map[string]mgrconfig.FocusArea)
	for _, area := range cfg.Experimental.FocusAreas {
		byName[area.Name] = area
		// On >=16 code files, no empty catch-all area should disable the executor filter.
		assert.False(t, area.Filter.Empty(), "unexpected catch-all area %+v", area)
	}

	_, hasRemoved := byName["drivers/net/removed.c"]
	assert.False(t, hasRemoved)
	_, hasArm64 := byName["arch/arm64/kvm/arm.c"]
	assert.False(t, hasArm64)

	drv0, ok := byName["drivers/net/drv0.c"]
	require.True(t, ok)
	assert.Equal(t, "drivers/net/drv0.c", drv0.Filter.Unit)
	assert.Equal(t, []string{"drv0_rx"}, drv0.Filter.Functions)
	assert.Equal(t, priorityShardWeight, drv0.Weight)
	assert.True(t, drv0.AdaptiveWeight)

	// Hot core unit keeps its surgical per-function shard, but is excluded from whole-unit modified_units.
	slub, ok := byName["mm/slub.c"]
	require.True(t, ok)
	assert.Equal(t, []string{"kmem_cache_alloc"}, slub.Filter.Functions)
	assert.Equal(t, defaultShardWeight, slub.Weight)

	hdr, ok := byName[headerInlinesArea]
	require.True(t, ok)
	assert.Equal(t, []string{"foo_hdr_helper"}, hdr.Filter.HeaderFunctions)
	assert.True(t, hdr.Filter.IncludeHeaderInlines)
}

func TestPatchFocusAreasFocusPaths(t *testing.T) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Linux,
			TargetArch: targets.AMD64,
			SysTarget:  targets.Get(targets.Linux, targets.AMD64),
		},
		Experimental: mgrconfig.Experimental{
			FocusPaths: []string{"^net/", "^drivers/net/", "^include/net/"},
		},
	}

	patches := [][]byte{
		[]byte(`diff --git a/net/core/dev.c b/net/core/dev.c
--- a/net/core/dev.c
+++ b/net/core/dev.c
@@ -10,3 +10,4 @@ static int netdev_rx(struct sk_buff *skb)
 	return 0;
`),
		[]byte(`diff --git a/fs/ext4/inode.c b/fs/ext4/inode.c
--- a/fs/ext4/inode.c
+++ b/fs/ext4/inode.c
@@ -10,3 +10,4 @@ static int ext4_do_iget(void)
 	return 0;
`),
		[]byte(`diff --git a/include/net/sock.h b/include/net/sock.h
--- a/include/net/sock.h
+++ b/include/net/sock.h
@@ -20,3 +20,4 @@ static inline int sock_hdr_helper(int x)
 	return x + 1;
`),
		[]byte(`diff --git a/include/linux/fs.h b/include/linux/fs.h
--- a/include/linux/fs.h
+++ b/include/linux/fs.h
@@ -20,3 +20,4 @@ static inline int fs_hdr_helper(int x)
 	return x + 1;
`),
	}
	baseHashes := map[string]string{"netdev_rx": "h1", "ext4_do_iget": "h1"}
	patchedHashes := map[string]string{"netdev_rx": "h2", "ext4_do_iget": "h2"}

	PatchFocusAreas(cfg, patches, baseHashes, patchedHashes)

	assert.Equal(t, []string{"include/net/sock.h", "net/core/dev.c"}, cfg.Experimental.ModifiedFiles)
	byName := make(map[string]mgrconfig.FocusArea)
	for _, area := range cfg.Experimental.FocusAreas {
		byName[area.Name] = area
		assert.False(t, area.Filter.Empty(), "scoped focus campaign must not add catch-all area")
	}
	_, hasExt4 := byName["fs/ext4/inode.c"]
	assert.False(t, hasExt4)

	netArea, ok := byName["net/core/dev.c"]
	require.True(t, ok)
	assert.Equal(t, []string{"netdev_rx"}, netArea.Filter.Functions)
	assert.Equal(t, priorityShardWeight, netArea.Weight)

	hdrArea, ok := byName[headerInlinesArea]
	require.True(t, ok)
	assert.Equal(t, []string{"sock_hdr_helper"}, hdrArea.Filter.HeaderFunctions)
	assert.False(t, hdrArea.Filter.IncludeHeaderInlines)

	subCtx, ok := byName[subsystemContextArea]
	require.True(t, ok)
	assert.Equal(t, []string{"^net/", "^drivers/net/", "^include/net/"}, subCtx.Filter.Files)
	assert.Equal(t, 1.0, subCtx.Weight)
}

func TestPrioritizeCandidates(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	ext4Long := fuzzer.Candidate{
		Prog:  makeTestProg(t, target, "ioctl$EXT4_IOC_MIGRATE", "close", "close"),
		Flags: fuzzer.ProgFromCorpus,
	}
	ext4ShortCorpus := fuzzer.Candidate{
		Prog:  makeTestProg(t, target, "syz_mount_image$ext4"),
		Flags: fuzzer.ProgFromCorpus,
	}
	ext4Seed := fuzzer.Candidate{
		Prog:  makeTestProg(t, target, "ioctl$EXT4_IOC_MIGRATE", "close"),
		Flags: fuzzer.ProgMinimized, // Not ProgFromCorpus -> short hand-written seed.
	}
	generalShort := fuzzer.Candidate{
		Prog:  makeTestProg(t, target, "getpid"),
		Flags: fuzzer.ProgFromCorpus,
	}
	generalLong := fuzzer.Candidate{
		Prog:  makeTestProg(t, target, "getpid", "getuid"),
		Flags: fuzzer.ProgFromCorpus,
	}
	deferredOcfs2 := fuzzer.Candidate{
		Prog:  makeTestProg(t, target, "syz_mount_image$ocfs2"),
		Flags: fuzzer.ProgFromCorpus,
	}

	candidates := []fuzzer.Candidate{
		deferredOcfs2,
		generalLong,
		ext4Long,
		generalShort,
		ext4ShortCorpus,
		ext4Seed,
	}
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Linux,
			TargetArch: targets.AMD64,
			Target:     target,
		},
		Experimental: mgrconfig.Experimental{
			ModifiedFiles: []string{"fs/ext4/inode.c"},
		},
	}

	focused, deferred := prioritizeCandidates(cfg, candidates)
	assert.Equal(t, 3, focused)
	assert.Equal(t, 1, deferred)
	labels := map[*prog.Prog]string{
		ext4Seed.Prog:        "ext4Seed",
		ext4ShortCorpus.Prog: "ext4ShortCorpus",
		ext4Long.Prog:        "ext4Long",
		generalShort.Prog:    "generalShort",
		generalLong.Prog:     "generalLong",
		deferredOcfs2.Prog:   "deferredOcfs2",
	}
	var gotOrder []string
	for _, c := range candidates {
		gotOrder = append(gotOrder, labels[c.Prog])
	}
	assert.Equal(t, []string{
		"ext4Seed",
		"ext4ShortCorpus",
		"ext4Long",
		"generalShort",
		"generalLong",
		"deferredOcfs2",
	}, gotOrder)
}

func TestPrioritizeCandidatesRoundRobinAcrossSubsystems(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)

	var candidates []fuzzer.Candidate
	for range 10 {
		candidates = append(candidates, fuzzer.Candidate{
			Prog:  makeTestProg(t, target, "bpf$MAP_CREATE"),
			Flags: fuzzer.ProgFromCorpus,
		})
	}
	rareExt4 := fuzzer.Candidate{
		Prog:  makeTestProg(t, target, "ioctl$EXT4_IOC_MIGRATE", "close", "close"),
		Flags: fuzzer.ProgFromCorpus,
	}
	candidates = append(candidates, rareExt4)

	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Linux,
			TargetArch: targets.AMD64,
			Target:     target,
		},
		Experimental: mgrconfig.Experimental{
			ModifiedFiles: []string{"kernel/bpf/verifier.c", "fs/ext4/inode.c"},
		},
	}

	focused, _ := prioritizeCandidates(cfg, candidates)
	assert.Equal(t, 11, focused)
	// The rare ext4 candidate (freq=1) must execute in wave 0 ahead of wave 0/1 bpf candidates (freq=10).
	assert.Same(t, rareExt4.Prog, candidates[0].Prog)

	t.Run("priority_subsystem_gets_wider_stride", func(t *testing.T) {
		var equalCands []fuzzer.Candidate
		for range 10 {
			equalCands = append(equalCands, fuzzer.Candidate{
				Prog:  makeTestProg(t, target, "ioctl$EXT4_IOC_MIGRATE"),
				Flags: fuzzer.ProgFromCorpus,
			})
		}
		for range 10 {
			equalCands = append(equalCands, fuzzer.Candidate{
				Prog:  makeTestProg(t, target, "bpf$MAP_CREATE"),
				Flags: fuzzer.ProgFromCorpus,
			})
		}
		focusedCount, _ := prioritizeCandidates(cfg, equalCands)
		assert.Equal(t, 20, focusedCount)
		// Wave 0 has 4 ext4 + 8 bpf = 12 candidates (focusedPriorityStride=8 vs focusedRoundRobinStride=4).
		bpfInWave0 := 0
		for _, c := range equalCands[:12] {
			if c.Prog.Calls[0].Meta.Name == "bpf$MAP_CREATE" {
				bpfInWave0++
			}
		}
		assert.Equal(t, 8, bpfInWave0)
	})
}

func makeTestProg(t *testing.T, target *prog.Target, callNames ...string) *prog.Prog {
	t.Helper()
	p := &prog.Prog{Target: target}
	for _, name := range callNames {
		meta := target.SyscallMap[name]
		require.NotNil(t, meta, "missing syscall %q", name)
		p.Calls = append(p.Calls, &prog.Call{Meta: meta, Props: prog.CallProps{}})
	}
	return p
}
