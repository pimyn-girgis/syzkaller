// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"bytes"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

const (
	symbolsArea          = "symbols"
	filesArea            = "files"
	headerInlinesArea    = "header_inlines"
	subsystemContextArea = "subsystem_context"

	shardedSeriesThreshold   = 3
	largeSeriesUnitFilterMin = 16
	defaultShardWeight       = 8.0
	priorityShardWeight      = 16.0
)

func PatchFocusAreas(cfg *mgrconfig.Config, gitPatches [][]byte, baseHashes, patchedHashes map[string]string) {
	direct := affectedFiles(gitPatches)
	relevant := filterRelevantKernelFiles(cfg, direct)
	focusRegexps := compileFocusPaths(cfg.Experimental.FocusPaths)
	scopedFiles, scoped := scopeFilesToFocusPaths(relevant, focusRegexps)
	cfg.Experimental.ModifiedFiles = scopedFiles
	cfg.Experimental.ModifiedSymbols = allModifiedSymbols(baseHashes, patchedHashes)

	if !scoped && len(gitPatches) <= shardedSeriesThreshold && len(direct) <= shardedSeriesThreshold {
		legacyPatchFocusAreas(cfg, direct, baseHashes, patchedHashes)
		return
	}
	shardedPatchFocusAreas(cfg, gitPatches, focusRegexps)
}

func legacyPatchFocusAreas(cfg *mgrconfig.Config, direct []string, baseHashes, patchedHashes map[string]string) {
	funcs := modifiedSymbols(baseHashes, patchedHashes)
	if len(funcs) > 0 {
		log.Logf(0, "adding modified_functions to focus areas: %q", funcs)
		var regexps []string
		for _, name := range funcs {
			regexps = append(regexps, fmt.Sprintf("^%s$", regexp.QuoteMeta(name)))
		}
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: symbolsArea,
				Filter: mgrconfig.CovFilterCfg{
					Functions: regexps,
				},
				Weight: 6.0,
			})
	}

	if len(direct) > 0 {
		log.Logf(0, "adding directly modified files to focus areas: %q", direct)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: filesArea,
				Filter: mgrconfig.CovFilterCfg{
					Files: direct,
				},
				Weight: 3.0,
			})
	}

	// Still fuzz the rest of the kernel.
	if len(cfg.Experimental.FocusAreas) > 0 {
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Weight: 1.0,
			})
	}
}

func shardedPatchFocusAreas(cfg *mgrconfig.Config, gitPatches [][]byte, focusRegexps []*regexp.Regexp) {
	parsed := parsePatchSeries(cfg, gitPatches)
	scopedByFocusPaths := parsed.applyFocusPaths(focusRegexps)
	existingNames := make(map[string]bool, len(cfg.Experimental.FocusAreas))
	hasEmptyFilter := false
	for _, area := range cfg.Experimental.FocusAreas {
		if area.Name != "" {
			existingNames[area.Name] = true
		}
		if area.Filter.Empty() {
			hasEmptyFilter = true
		}
	}

	codeFiles := slices.Sorted(maps.Keys(parsed.codeFileFuncs))
	addedShards := 0
	priorityShards := 0
	for _, file := range codeFiles {
		if existingNames[file] {
			continue
		}
		funcs := slices.Sorted(maps.Keys(parsed.codeFileFuncs[file]))
		weight := defaultShardWeight
		if isPrioritySubsystemPath(file) {
			weight = priorityShardWeight
			priorityShards++
		}
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas, mgrconfig.FocusArea{
			Name: file,
			Filter: mgrconfig.CovFilterCfg{
				Unit:      file,
				Functions: funcs,
			},
			Weight:         weight,
			AdaptiveWeight: true,
		})
		existingNames[file] = true
		addedShards++
	}

	includeHeaderInlines := len(cfg.Experimental.ModifiedSymbols) > 0 && !scopedByFocusPaths
	if (len(parsed.headerFiles) > 0 && includeHeaderInlines || len(parsed.headerFuncs) > 0) &&
		!existingNames[headerInlinesArea] {
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas, mgrconfig.FocusArea{
			Name: headerInlinesArea,
			Filter: mgrconfig.CovFilterCfg{
				HeaderFunctions:      slices.Sorted(maps.Keys(parsed.headerFuncs)),
				IncludeHeaderInlines: includeHeaderInlines,
			},
			Weight:         4.0,
			AdaptiveWeight: true,
		})
		existingNames[headerInlinesArea] = true
	}

	if len(cfg.Experimental.FocusAreas) == 0 {
		return
	}

	// On large series (such as stable/LTS RCs), omit the unfiltered kernel catch-all so the
	// executor coverage filter stays tightly scoped. When FocusPaths scopes a campaign to a small
	// number of modified files (e.g. KVM), include a low-weight subsystem-wide coverage area so
	// multi-step state-machine setup within that subsystem still receives coverage feedback.
	switch {
	case scopedByFocusPaths && len(codeFiles) < largeSeriesUnitFilterMin && !existingNames[subsystemContextArea]:
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas, mgrconfig.FocusArea{
			Name: subsystemContextArea,
			Filter: mgrconfig.CovFilterCfg{
				Files: slices.Clone(cfg.Experimental.FocusPaths),
			},
			Weight: 1.0,
		})
	case !scopedByFocusPaths && len(codeFiles) < largeSeriesUnitFilterMin && !hasEmptyFilter:
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas, mgrconfig.FocusArea{
			Weight: 1.0,
		})
	}
	log.Logf(0, "configured sharded patch focus: %d file shards (%d priority), %d headers (%d changed symbols)",
		addedShards, priorityShards, len(parsed.headerFiles), len(cfg.Experimental.ModifiedSymbols))
}

type parsedSeriesInfo struct {
	codeFileFuncs   map[string]map[string]struct{}
	headerFiles     map[string]struct{}
	headerFileFuncs map[string]map[string]struct{}
	headerFuncs     map[string]struct{}
}

var diffHeaderFileRe = regexp.MustCompile(`^diff.* b/([^\s]+)$`)

func parsePatchSeries(cfg *mgrconfig.Config, gitPatches [][]byte) parsedSeriesInfo {
	info := parsedSeriesInfo{
		codeFileFuncs:   make(map[string]map[string]struct{}),
		headerFiles:     make(map[string]struct{}),
		headerFileFuncs: make(map[string]map[string]struct{}),
		headerFuncs:     make(map[string]struct{}),
	}
	deleted := make(map[string]bool)
	for _, patch := range gitPatches {
		curFile := ""
		inHunk := false
		for rawLine := range bytes.SplitSeq(patch, []byte("\n")) {
			line := string(bytes.TrimSuffix(rawLine, []byte("\r")))
			if m := diffHeaderFileRe.FindStringSubmatch(line); m != nil {
				curFile = m[1]
				inHunk = false
				continue
			}
			if curFile == "" {
				continue
			}
			if strings.HasPrefix(line, "+++ ") {
				if strings.TrimSpace(line[4:]) == "/dev/null" {
					deleted[curFile] = true
					curFile = ""
				} else {
					delete(deleted, curFile)
				}
				continue
			}
			if strings.HasPrefix(line, "--- ") {
				continue
			}
			if !isRelevantKernelFile(cfg, curFile) {
				continue
			}
			if strings.HasPrefix(line, "@@ ") {
				inHunk = true
				info.recordFile(curFile)
				if _, rest, ok := strings.Cut(line[3:], "@@"); ok {
					ctx := strings.TrimPrefix(rest, " ")
					if ctx != "" && isIdentStart(ctx[0]) {
						info.recordFuncs(curFile, extractTopLevelFunctions(ctx))
					}
				}
				continue
			}
			if !inHunk || len(line) <= 1 {
				continue
			}
			prefix := line[0]
			if prefix != '+' && prefix != '-' && prefix != ' ' {
				continue
			}
			body := line[1:]
			if body != "" && isIdentStart(body[0]) {
				info.recordFuncs(curFile, extractTopLevelFunctions(body))
			}
		}
	}
	for file := range deleted {
		delete(info.codeFileFuncs, file)
		delete(info.headerFiles, file)
		delete(info.headerFileFuncs, file)
	}
	info.rebuildHeaderFuncs()
	return info
}

func (info *parsedSeriesInfo) recordFile(file string) {
	if isHeaderFile(file) {
		info.headerFiles[file] = struct{}{}
		if info.headerFileFuncs[file] == nil {
			info.headerFileFuncs[file] = make(map[string]struct{})
		}
		return
	}
	if info.codeFileFuncs[file] == nil {
		info.codeFileFuncs[file] = make(map[string]struct{})
	}
}

func (info *parsedSeriesInfo) recordFuncs(file string, funcs []string) {
	info.recordFile(file)
	if isHeaderFile(file) {
		set := info.headerFileFuncs[file]
		for _, fn := range funcs {
			set[fn] = struct{}{}
		}
		return
	}
	set := info.codeFileFuncs[file]
	for _, fn := range funcs {
		set[fn] = struct{}{}
	}
}

func (info *parsedSeriesInfo) rebuildHeaderFuncs() {
	clear(info.headerFuncs)
	for file, fns := range info.headerFileFuncs {
		if manager.IsHotCoreKernelUnit(file) {
			continue
		}
		for fn := range fns {
			info.headerFuncs[fn] = struct{}{}
		}
	}
}

func (info *parsedSeriesInfo) applyFocusPaths(focusRegexps []*regexp.Regexp) bool {
	if len(focusRegexps) == 0 {
		return false
	}
	matchedCode := make(map[string]map[string]struct{})
	for file, fns := range info.codeFileFuncs {
		if matchesAnyRegexp(file, focusRegexps) {
			matchedCode[file] = fns
		}
	}
	matchedHeaders := make(map[string]struct{})
	matchedHeaderFuncs := make(map[string]map[string]struct{})
	for file := range info.headerFiles {
		if matchesAnyRegexp(file, focusRegexps) {
			matchedHeaders[file] = struct{}{}
			if fns := info.headerFileFuncs[file]; fns != nil {
				matchedHeaderFuncs[file] = fns
			}
		}
	}
	if len(matchedCode) == 0 && len(matchedHeaderFuncs) == 0 {
		return false
	}
	info.codeFileFuncs = matchedCode
	info.headerFiles = matchedHeaders
	info.headerFileFuncs = matchedHeaderFuncs
	info.rebuildHeaderFuncs()
	return true
}

func compileFocusPaths(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, expr := range patterns {
		re, err := regexp.Compile(expr)
		if err != nil {
			log.Logf(0, "invalid focus path regexp %q: %v", expr, err)
			continue
		}
		compiled = append(compiled, re)
	}
	return compiled
}

func matchesAnyRegexp(path string, regexps []*regexp.Regexp) bool {
	clean := strings.TrimPrefix(filepath.ToSlash(path), "./")
	return slices.ContainsFunc(regexps, func(re *regexp.Regexp) bool {
		return re.MatchString(clean)
	})
}

func scopeFilesToFocusPaths(files []string, focusRegexps []*regexp.Regexp) ([]string, bool) {
	if len(focusRegexps) == 0 {
		return files, false
	}
	var matched []string
	for _, file := range files {
		if matchesAnyRegexp(file, focusRegexps) {
			matched = append(matched, file)
		}
	}
	if len(matched) == 0 {
		return files, false
	}
	return matched, true
}

var priorityPathPrefixes = []string{
	"net/",
	"drivers/net/",
	"drivers/bluetooth/",
	"drivers/nfc/",
	"drivers/infiniband/",
	"include/net/",
	"include/rdma/",
	"virt/kvm/",
	"drivers/vhost/",
	"drivers/virtio/",
	"kernel/bpf/",
	"include/linux/bpf",
	"io_uring/",
	"security/",
}

// isPrioritySubsystemPath reports whether path belongs to a high-priority security/virtualization
// or networking subsystem that receives boosted focus weight and candidate scheduling share.
func isPrioritySubsystemPath(path string) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "./")
	for _, prefix := range priorityPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	if (strings.HasPrefix(path, "arch/") || strings.HasPrefix(path, "include/")) &&
		strings.Contains(path, "/kvm") {
		return true
	}
	return false
}

func isHeaderFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".h" || ext == ".inc"
}

var nonFuzzedPrefixes = []string{
	"Documentation/",
	"tools/",
	"scripts/",
	"samples/",
	"LICENSES/",
	"usr/",
	"certs/",
	".github/",
}

func filterRelevantKernelFiles(cfg *mgrconfig.Config, files []string) []string {
	var ret []string
	for _, f := range files {
		if isRelevantKernelFile(cfg, f) {
			ret = append(ret, f)
		}
	}
	return ret
}

func isRelevantKernelFile(cfg *mgrconfig.Config, path string) bool {
	path = strings.TrimPrefix(filepath.ToSlash(path), "./")
	if path == "" {
		return false
	}
	for _, prefix := range nonFuzzedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	if rest, ok := strings.CutPrefix(path, "arch/"); ok {
		if archDir, _, hasSlash := strings.Cut(rest, "/"); hasSlash {
			if targetArch := kernelHeaderArch(cfg); targetArch != "" && archDir != targetArch && archDir != "um" {
				return false
			}
		}
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".c", ".h", ".rs", ".inc":
		return true
	default:
		return false
	}
}

func kernelHeaderArch(cfg *mgrconfig.Config) string {
	if cfg == nil {
		return ""
	}
	if cfg.SysTarget != nil && cfg.SysTarget.OS == targets.Linux {
		return cfg.SysTarget.KernelHeaderArch
	}
	if cfg.TargetOS == targets.Linux && cfg.TargetArch != "" {
		if sysTarget := targets.Get(cfg.TargetOS, cfg.TargetArch); sysTarget != nil {
			return sysTarget.KernelHeaderArch
		}
	}
	return ""
}

var cNonFuncKeywords = map[string]bool{
	"if":          true,
	"for":         true,
	"while":       true,
	"switch":      true,
	"return":      true,
	"sizeof":      true,
	"typeof":      true,
	"__typeof__":  true,
	"alignof":     true,
	"__alignof__": true,
	"offsetof":    true,
	"struct":      true,
	"union":       true,
	"enum":        true,
	"typedef":     true,
}

var (
	syscallDefineRe = regexp.MustCompile(`^(?:COMPAT_)?SYSCALL_DEFINE[0-6]\(\s*([A-Za-z_][A-Za-z0-9_]*)`)
	bpfCallDefineRe = regexp.MustCompile(`^BPF_CALL_[0-5]\(\s*([A-Za-z_][A-Za-z0-9_]*)`)
)

func extractTopLevelFunctions(line string) []string {
	s := stripLeadingAnnotations(strings.TrimSpace(line))
	if s == "" {
		return nil
	}
	if m := syscallDefineRe.FindStringSubmatch(s); m != nil {
		name := m[1]
		if strings.HasPrefix(s, "COMPAT_") {
			return []string{"__do_compat_sys_" + name, "__se_compat_sys_" + name, "__ia32_compat_sys_" + name}
		}
		return []string{"__do_sys_" + name, "__se_sys_" + name, "__x64_sys_" + name, "__ia32_sys_" + name}
	}
	if m := bpfCallDefineRe.FindStringSubmatch(s); m != nil {
		return []string{m[1], "____" + m[1]}
	}
	parenIdx := strings.IndexByte(s, '(')
	if parenIdx <= 0 {
		return nil
	}
	prefix := strings.TrimSpace(s[:parenIdx])
	end := len(prefix)
	start := end
	for start > 0 && isIdentChar(prefix[start-1]) {
		start--
	}
	if start == end {
		return nil
	}
	ident := prefix[start:end]
	if !isIdentStart(ident[0]) || cNonFuncKeywords[ident] || !hasLowerASCII(ident) {
		return nil
	}
	return []string{ident}
}

func stripLeadingAnnotations(s string) string {
	for strings.HasPrefix(s, "__") {
		openIdx := strings.IndexByte(s, '(')
		if openIdx <= 2 {
			break
		}
		onlyIdent := true
		for i := range openIdx {
			if !isIdentChar(s[i]) {
				onlyIdent = false
				break
			}
		}
		if !onlyIdent {
			break
		}
		depth := 0
		closeIdx := -1
		for i := openIdx; i < len(s); i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					closeIdx = i
				}
			}
			if closeIdx != -1 {
				break
			}
		}
		if closeIdx == -1 {
			break
		}
		rest := strings.TrimSpace(s[closeIdx+1:])
		if !strings.Contains(rest, "(") {
			break
		}
		s = rest
	}
	return s
}

func isIdentStart(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_'
}

func isIdentChar(ch byte) bool {
	return isIdentStart(ch) || ch >= '0' && ch <= '9'
}

func hasLowerASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 'a' && s[i] <= 'z' {
			return true
		}
	}
	return false
}

func affectedFiles(gitPatches [][]byte) []string {
	directMap := make(map[string]struct{})
	for _, patch := range gitPatches {
		for _, diff := range vcs.ParseGitDiff(patch) {
			directMap[diff.Name] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(directMap))
}

func allModifiedSymbols(baseHashes, patchedHashes map[string]string) []string {
	if len(patchedHashes) == 0 {
		return nil
	}
	var ret []string
	for name, hash := range patchedHashes {
		if baseHash, ok := baseHashes[name]; !ok || baseHash != hash {
			ret = append(ret, name)
		}
	}
	slices.Sort(ret)
	return ret
}

// If there are too many different symbols, they are no longer specific enough.
// Don't use them to focus the fuzzer.
const modifiedSymbolThreshold = 0.05

func modifiedSymbols(baseHashes, patchedHashes map[string]string) []string {
	var ret []string
	for name, hash := range patchedHashes {
		if baseHash, ok := baseHashes[name]; !ok || baseHash != hash {
			ret = append(ret, name)
			if float64(len(ret)) > float64(len(patchedHashes))*modifiedSymbolThreshold {
				return nil
			}
		}
	}
	slices.Sort(ret)
	return ret
}
