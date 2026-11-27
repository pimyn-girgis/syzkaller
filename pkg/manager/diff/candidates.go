// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"cmp"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/syzkaller/prog"
)

type callTier uint8

const (
	callGeneral callTier = iota
	callFocused
	callDeferred
)

type syscallFocusInfo struct {
	tier   callTier
	tokens []string
}

type rankedCandidate struct {
	cand fuzzer.Candidate
	key  uint64
}

const (
	shortHandwrittenSeedMaxCalls = 12
	focusedRoundRobinStride      = 4
	focusedPriorityStride        = 8
)

// prioritizeCandidates orders candidates in-place so seeds targeting modified subsystems run first
// in stratified round-robin waves across all modified subsystems/files, general syscalls run second,
// and heavy pseudo-syscalls for unmodified subsystems (such as corrupted filesystem image mounts for
// untouched filesystems) are deferred to the end.
func prioritizeCandidates(cfg *mgrconfig.Config, candidates []fuzzer.Candidate) (focused, deferred int) {
	if len(candidates) <= 1 {
		return 0, 0
	}
	var callInfos []syscallFocusInfo
	var priorityTokens map[string]bool
	if cfg != nil && cfg.Target != nil && len(cfg.Experimental.ModifiedFiles) > 0 {
		callInfos, priorityTokens = classifyTargetSyscalls(cfg)
	}
	if len(callInfos) == 0 {
		sortPlainCandidates(candidates)
		return 0, 0
	}

	type focusedEntry struct {
		origIdx  int
		tokens   []string
		intraKey uint32
	}
	var focusedEntries []focusedEntry
	tokenFreq := make(map[string]int)
	ranked := make([]rankedCandidate, 0, len(candidates))

	for i, cand := range candidates {
		tier, matched := candidateFocusMatch(cand.Prog, callInfos)
		intra := candidateIntraKey(cand)
		switch tier {
		case callFocused:
			focused++
			for _, tok := range matched {
				tokenFreq[tok]++
			}
			focusedEntries = append(focusedEntries, focusedEntry{
				origIdx:  i,
				tokens:   matched,
				intraKey: intra,
			})
		case callDeferred:
			deferred++
			ranked = append(ranked, rankedCandidate{
				cand: cand,
				key:  (uint64(2) << 60) | uint64(intra),
			})
		default:
			ranked = append(ranked, rankedCandidate{
				cand: cand,
				key:  (uint64(1) << 60) | uint64(intra),
			})
		}
	}

	// Group focused candidates by their rarest matched modified token so large multi-subsystem
	// series (like stable/LTS RCs) immediately exercise every modified subsystem in round-robin waves
	// rather than letting one high-volume subsystem monopolize early execution.
	buckets := make(map[string][]focusedEntry)
	for _, entry := range focusedEntries {
		bestTok := ""
		bestFreq := int(^uint(0) >> 1)
		for _, tok := range entry.tokens {
			f := tokenFreq[tok]
			if bestTok == "" || f < bestFreq || (f == bestFreq && tok < bestTok) {
				bestTok = tok
				bestFreq = f
			}
		}
		buckets[bestTok] = append(buckets[bestTok], entry)
	}

	for bestTok, items := range buckets {
		slices.SortStableFunc(items, func(a, b focusedEntry) int {
			return cmp.Compare(a.intraKey, b.intraKey)
		})
		stride := focusedRoundRobinStride
		if priorityTokens[bestTok] {
			stride = focusedPriorityStride
		}
		freq := uint64(min(tokenFreq[bestTok], 0xfffff))
		for rankInBucket, entry := range items {
			wave := uint64(min(rankInBucket/stride, 0x3ffff))
			rankClamped := uint64(min(rankInBucket, 0x3ffff))
			key := (wave << 38) | (freq << 18) | rankClamped
			ranked = append(ranked, rankedCandidate{
				cand: candidates[entry.origIdx],
				key:  key,
			})
		}
	}

	slices.SortStableFunc(ranked, func(a, b rankedCandidate) int {
		return cmp.Compare(a.key, b.key)
	})
	for i, item := range ranked {
		candidates[i] = item.cand
	}
	return focused, deferred
}

func sortPlainCandidates(candidates []fuzzer.Candidate) {
	ranked := make([]rankedCandidate, len(candidates))
	for i, cand := range candidates {
		ranked[i] = rankedCandidate{
			cand: cand,
			key:  uint64(candidateIntraKey(cand)),
		}
	}
	slices.SortStableFunc(ranked, func(a, b rankedCandidate) int {
		return cmp.Compare(a.key, b.key)
	})
	for i, item := range ranked {
		candidates[i] = item.cand
	}
}

func candidateIntraKey(cand fuzzer.Candidate) uint32 {
	nCalls := 0
	if cand.Prog != nil {
		nCalls = len(cand.Prog.Calls)
	}
	// Short hand-written test seeds run first, minimized corpus DB entries run second,
	// and large unminimized multi-dozen-call test files run third within the bucket.
	originRank := uint32(1)
	if cand.Flags&fuzzer.ProgFromCorpus == 0 {
		if nCalls <= shortHandwrittenSeedMaxCalls {
			originRank = 0
		} else {
			originRank = 2
		}
	}
	callCount := uint32(min(nCalls, 0x3ffff))
	return (originRank << 18) | callCount
}

func candidateFocusMatch(p *prog.Prog, callInfos []syscallFocusInfo) (callTier, []string) {
	if p == nil {
		return callGeneral, nil
	}
	var matched []string
	for _, call := range p.Calls {
		if call.Meta == nil || call.Meta.ID < 0 || call.Meta.ID >= len(callInfos) {
			continue
		}
		info := callInfos[call.Meta.ID]
		switch info.tier {
		case callDeferred:
			return callDeferred, nil
		case callFocused:
			for _, tok := range info.tokens {
				if !slices.Contains(matched, tok) {
					matched = append(matched, tok)
				}
			}
		}
	}
	if len(matched) > 0 {
		return callFocused, matched
	}
	return callGeneral, nil
}

var (
	pathMatcherMu    sync.Mutex
	pathMatcherCache = make(map[string]*subsystem.PathMatcher)
)

func cachedPathMatcher(os string, list []*subsystem.Subsystem) *subsystem.PathMatcher {
	pathMatcherMu.Lock()
	defer pathMatcherMu.Unlock()
	if m := pathMatcherCache[os]; m != nil {
		return m
	}
	m := subsystem.MakePathMatcher(list)
	pathMatcherCache[os] = m
	return m
}

func classifyTargetSyscalls(cfg *mgrconfig.Config) ([]syscallFocusInfo, map[string]bool) {
	modifiedTokens := extractModifiedTokens(cfg.Experimental.ModifiedFiles)
	var priorityFiles []string
	for _, file := range cfg.Experimental.ModifiedFiles {
		if isPrioritySubsystemPath(file) {
			priorityFiles = append(priorityFiles, file)
		}
	}
	priorityTokens := extractModifiedTokens(priorityFiles)
	modifiedSubTokens := make(map[string][]string)
	unmodifiedSubCalls := make(map[string]bool)

	if cfg.TargetOS != "" && subsystem.HasList(cfg.TargetOS) {
		list := subsystem.GetList(cfg.TargetOS)
		matcher := cachedPathMatcher(cfg.TargetOS, list)
		modifiedSubs := make(map[*subsystem.Subsystem]bool)
		prioritySubs := make(map[*subsystem.Subsystem]bool)
		for _, file := range cfg.Experimental.ModifiedFiles {
			prio := isPrioritySubsystemPath(file)
			for _, sub := range matcher.Match(file) {
				modifiedSubs[sub] = true
				if prio {
					prioritySubs[sub] = true
				}
			}
		}
		for _, sub := range list {
			if modifiedSubs[sub] {
				subTok := normalizeToken(sub.Name)
				if subTok == "" {
					subTok = "sub_unknown"
				}
				for _, sc := range sub.Syscalls {
					if !slices.Contains(modifiedSubTokens[sc], subTok) {
						modifiedSubTokens[sc] = append(modifiedSubTokens[sc], subTok)
					}
				}
				if prioritySubs[sub] {
					addModifiedToken(priorityTokens, subTok)
				}
				if len(subTok) >= 3 && !genericPathTokens[subTok] {
					addModifiedToken(modifiedTokens, subTok)
				}
			} else {
				for _, sc := range sub.Syscalls {
					unmodifiedSubCalls[sc] = true
				}
			}
		}
	}

	infos := make([]syscallFocusInfo, len(cfg.Target.Syscalls))
	for i, meta := range cfg.Target.Syscalls {
		if meta == nil {
			continue
		}
		infos[i] = classifySingleSyscall(meta, modifiedTokens, modifiedSubTokens, unmodifiedSubCalls)
	}
	return infos, priorityTokens
}

func classifySingleSyscall(meta *prog.Syscall, modifiedTokens map[string]bool,
	modifiedSubTokens map[string][]string, unmodifiedSubCalls map[string]bool) syscallFocusInfo {
	var matched []string
	addTok := func(tok string) {
		if tok != "" && !slices.Contains(matched, tok) {
			matched = append(matched, tok)
		}
	}
	for _, tok := range modifiedSubTokens[meta.Name] {
		addTok(tok)
	}
	for _, tok := range modifiedSubTokens[meta.CallName] {
		addTok(tok)
	}

	for _, fsPrefix := range []string{"syz_mount_image$", "fsopen$"} {
		if fsType, ok := strings.CutPrefix(meta.Name, fsPrefix); ok {
			norm := normalizeToken(fsType)
			if modifiedTokens[norm] {
				addTok(norm)
				return syscallFocusInfo{tier: callFocused, tokens: matched}
			}
			if len(matched) > 0 {
				return syscallFocusInfo{tier: callFocused, tokens: matched}
			}
			return syscallFocusInfo{tier: callDeferred}
		}
	}

	for _, tok := range matchSyscallTokens(meta, modifiedTokens) {
		addTok(tok)
	}
	if len(matched) > 0 {
		return syscallFocusInfo{tier: callFocused, tokens: matched}
	}
	if unmodifiedSubCalls[meta.Name] || unmodifiedSubCalls[meta.CallName] {
		return syscallFocusInfo{tier: callDeferred}
	}
	return syscallFocusInfo{tier: callGeneral}
}

func extractModifiedTokens(files []string) map[string]bool {
	tokens := make(map[string]bool)
	for _, raw := range files {
		clean := strings.TrimPrefix(filepath.ToSlash(raw), "./")
		parts := strings.Split(clean, "/")
		if len(parts) == 0 {
			continue
		}
		for _, dir := range parts[:len(parts)-1] {
			tok := normalizeToken(dir)
			if len(tok) >= 3 && !genericPathTokens[tok] {
				addModifiedToken(tokens, tok)
			}
		}
		base := parts[len(parts)-1]
		stem := normalizeToken(strings.TrimSuffix(base, filepath.Ext(base)))
		if len(stem) >= 4 && !genericPathTokens[stem] && !genericStemTokens[stem] {
			addModifiedToken(tokens, stem)
		}
		for _, prefix := range kernelModuleStemPrefixes {
			if rem, ok := strings.CutPrefix(stem, prefix); ok && len(rem) >= 3 {
				if !genericPathTokens[rem] && !genericStemTokens[rem] {
					addModifiedToken(tokens, rem)
				}
			}
		}
	}
	return tokens
}

func addModifiedToken(tokens map[string]bool, tok string) {
	tokens[tok] = true
	for _, alias := range tokenAliases[tok] {
		tokens[alias] = true
	}
}

func matchSyscallTokens(meta *prog.Syscall, modifiedTokens map[string]bool) []string {
	if len(modifiedTokens) == 0 {
		return nil
	}
	var matched []string
	callLower := normalizeToken(meta.CallName)
	if !genericMultiplexerCalls[callLower] {
		matched = appendTokenMatches(matched, callLower, modifiedTokens)
	}
	if _, variant, ok := strings.Cut(meta.Name, "$"); ok {
		matched = appendTokenMatches(matched, normalizeToken(variant), modifiedTokens)
	}
	return matched
}

func appendTokenMatches(dst []string, name string, modifiedTokens map[string]bool) []string {
	if name == "" {
		return dst
	}
	add := func(tok string) {
		if !slices.Contains(dst, tok) {
			dst = append(dst, tok)
		}
	}
	if len(name) >= 3 && !genericSyscallTokens[name] && modifiedTokens[name] {
		add(name)
	}
	parts := strings.Split(name, "_")
	for i, p := range parts {
		if len(p) >= 3 && !genericSyscallTokens[p] && modifiedTokens[p] {
			add(p)
		}
		if i+1 < len(parts) && parts[i] != "" && parts[i+1] != "" {
			compound := parts[i] + "_" + parts[i+1]
			if len(compound) >= 4 && !genericSyscallTokens[compound] && modifiedTokens[compound] {
				add(compound)
			}
		}
	}
	return dst
}

func normalizeToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(s, "-", "_")
}

var kernelModuleStemPrefixes = []string{
	"sch_", "cls_", "act_", "nft_", "xt_", "ipt_", "ip6t_", "ebt_", "arpt_", "nf_",
}

var tokenAliases = map[string][]string{
	"fat":        {"msdos", "vfat"},
	"isofs":      {"iso9660"},
	"hfsplus":    {"hfs"},
	"nilfs2":     {"nilfs"},
	"smb":        {"cifs", "smb3"},
	"cifs":       {"smb", "smb3"},
	"v9fs":       {"9p"},
	"netfilter":  {"nft"},
	"sound":      {"snd", "alsa"},
	"dri":        {"drm"},
	"wireless":   {"80211", "nl80211"},
	"mac80211":   {"80211", "nl80211"},
	"infiniband": {"rdma", "uverbs"},
}

var genericPathTokens = map[string]bool{
	"arch": true, "asm": true, "asm_generic": true, "block": true, "char": true,
	"common": true, "core": true, "drivers": true, "fs": true, "generic": true,
	"include": true, "internal": true, "kernel": true, "lib": true, "linux": true,
	"mm": true, "net": true, "security": true, "selftests": true, "tests": true,
	"uapi": true, "um": true, "virt": true, "x86": true, "x86_64": true,
}

var genericStemTokens = map[string]bool{
	"addr": true, "alloc": true, "attr": true, "bus": true, "client": true,
	"compat": true, "config": true, "dcache": true, "debug": true, "debugfs": true,
	"device": true, "dir": true, "driver": true, "entry": true, "file": true,
	"files": true, "hash": true, "helper": true, "helpers": true, "host": true,
	"info": true, "init": true, "inode": true, "ioctl": true, "ioctl32": true,
	"link": true, "list": true, "lock": true, "locks": true, "main": true,
	"memory": true, "mmap": true, "mutex": true, "namei": true, "open": true,
	"ops": true, "page": true, "poll": true, "port": true, "proc": true,
	"read": true, "route": true, "select": true, "server": true, "skbuff": true,
	"slab": true, "slub": true, "sock": true, "socket": true, "stat": true,
	"super": true, "sysfs": true, "table": true, "task": true, "time": true,
	"timer": true, "trace": true, "tree": true, "types": true, "util": true,
	"utils": true, "work": true, "write": true,
}

var genericMultiplexerCalls = map[string]bool{
	"accept": true, "accept4": true, "bind": true, "close": true, "connect": true,
	"fcntl": true, "getsockopt": true, "ioctl": true, "listen": true, "mkdir": true,
	"mkdirat": true, "mmap": true, "mprotect": true, "munmap": true, "open": true,
	"openat": true, "poll": true, "ppoll": true, "prctl": true, "pread64": true,
	"preadv": true, "pwrite64": true, "pwritev": true, "read": true, "readv": true,
	"recvfrom": true, "recvmmsg": true, "recvmsg": true, "sendfile": true,
	"sendmmsg": true, "sendmsg": true, "sendto": true, "setsockopt": true,
	"socket": true, "socketpair": true, "write": true, "writev": true,
}

var genericSyscallTokens = map[string]bool{
	"add": true, "attach": true, "attr": true, "char": true, "close": true,
	"cmd": true, "common": true, "connect": true, "core": true, "create": true,
	"ctl": true, "data": true, "del": true, "detach": true, "dev": true,
	"dir": true, "emit": true, "enable": true, "enter": true, "event": true,
	"exit": true, "file": true, "flags": true, "generic": true, "get": true,
	"handle": true, "info": true, "init": true, "int": true, "ioc": true,
	"ioctl": true, "kern": true, "linux": true, "list": true, "lock": true,
	"map": true, "mem": true, "mmap": true, "mode": true, "msg": true,
	"munmap": true, "name": true, "net": true, "new": true, "next": true,
	"off": true, "open": true, "openat": true, "opt": true, "page": true,
	"path": true, "poll": true, "port": true, "proc": true, "procfs": true,
	"prog": true, "ptr": true, "raw": true, "read": true, "recv": true,
	"reg": true, "register": true, "req": true, "res": true, "run": true,
	"send": true, "set": true, "setup": true, "size": true, "sock": true,
	"socket": true, "stat": true, "status": true, "str": true, "sub": true,
	"sys": true, "sysctl": true, "sysfs": true, "syz": true, "table": true,
	"test": true, "time": true, "type": true, "user": true, "val": true,
	"wait": true, "write": true,
}
