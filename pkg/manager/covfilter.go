// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package manager implements the main fuzzing manager logic, crash processing, and report generation.
package manager

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
)

var hotCoreUnitPrefixes = []string{
	"arch/x86/entry/",
	"arch/x86/lib/",
	"arch/arm64/kernel/entry",
	"kernel/sched/",
	"kernel/locking/",
	"kernel/rcu/",
	"kernel/time/",
	"kernel/irq/",
	"kernel/printk/",
	"mm/kasan/",
	"lib/",
}

var hotCoreUnits = map[string]bool{
	"kernel/kcov.c":              true,
	"kernel/softirq.c":           true,
	"kernel/signal.c":            true,
	"kernel/exit.c":              true,
	"kernel/fork.c":              true,
	"kernel/cred.c":              true,
	"mm/page_alloc.c":            true,
	"mm/slub.c":                  true,
	"mm/slab_common.c":           true,
	"mm/util.c":                  true,
	"mm/mmap.c":                  true,
	"mm/memory.c":                true,
	"mm/memcontrol.c":            true,
	"fs/file.c":                  true,
	"fs/file_table.c":            true,
	"fs/open.c":                  true,
	"fs/read_write.c":            true,
	"fs/namei.c":                 true,
	"fs/dcache.c":                true,
	"fs/inode.c":                 true,
	"net/socket.c":               true,
	"include/linux/memcontrol.h": true,
	"include/linux/mm.h":         true,
	"include/linux/mm_inline.h":  true,
	"include/linux/pagemap.h":    true,
	"include/linux/slab.h":       true,
	"include/linux/sched.h":      true,
	"include/linux/skbuff.h":     true,
	"include/linux/rcupdate.h":   true,
	"include/linux/spinlock.h":   true,
	"include/linux/mutex.h":      true,
	"include/linux/fs.h":         true,
	"include/linux/dcache.h":     true,
}

// IsHotCoreKernelUnit reports whether path is an ultra-hot core kernel compile unit executed
// across most syscalls, where whole-unit coverage filtering would destroy focus selectivity.
func IsHotCoreKernelUnit(path string) bool {
	path = cleanUnitName(path)
	if hotCoreUnits[path] {
		return true
	}
	for _, prefix := range hotCoreUnitPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// BaseSymbolName strips compiler-generated clone/split suffixes (such as .isra.0, .cold, .llvm.*).
func BaseSymbolName(name string) string {
	if idx := strings.IndexByte(name, '.'); idx > 0 {
		return name[:idx]
	}
	return name
}

func cleanUnitName(name string) string {
	return strings.TrimPrefix(filepath.ToSlash(name), "./")
}

type covFilterIndex struct {
	rg              *backend.Impl
	unitsByName     map[string][]*backend.CompileUnit
	unitSyms        map[string][]*backend.Symbol
	symsByBase      map[string][]*backend.Symbol
	symUnitCount    map[string]int
	modifiedSyms    map[string]struct{}
	modifiedFiles   map[string]struct{}
	modifiedSubdirs map[string]struct{}
}

func newCovFilterIndex(rg *backend.Impl, modifiedSyms, modifiedFiles []string) *covFilterIndex {
	idx := &covFilterIndex{
		rg:              rg,
		unitsByName:     make(map[string][]*backend.CompileUnit, len(rg.Units)),
		unitSyms:        make(map[string][]*backend.Symbol, len(rg.Units)),
		symsByBase:      make(map[string][]*backend.Symbol, len(rg.Symbols)),
		symUnitCount:    make(map[string]int, len(rg.Symbols)),
		modifiedSyms:    make(map[string]struct{}, len(modifiedSyms)*2),
		modifiedFiles:   make(map[string]struct{}, len(modifiedFiles)),
		modifiedSubdirs: make(map[string]struct{}, len(modifiedFiles)),
	}
	for _, u := range rg.Units {
		name := cleanUnitName(u.Name)
		idx.unitsByName[name] = append(idx.unitsByName[name], u)
	}
	seenSymUnit := make(map[string]string, len(rg.Symbols))
	seenSymMulti := make(map[string]map[string]struct{})
	for _, sym := range rg.Symbols {
		base := BaseSymbolName(sym.Name)
		idx.symsByBase[base] = append(idx.symsByBase[base], sym)
		unitName := ""
		if sym.Unit != nil {
			unitName = cleanUnitName(sym.Unit.Name)
			idx.unitSyms[unitName] = append(idx.unitSyms[unitName], sym)
		}
		if prev, ok := seenSymUnit[base]; !ok {
			seenSymUnit[base] = unitName
			idx.symUnitCount[base] = 1
		} else if prev != unitName {
			multi := seenSymMulti[base]
			if multi == nil {
				multi = map[string]struct{}{prev: {}}
				seenSymMulti[base] = multi
			}
			if _, exists := multi[unitName]; !exists {
				multi[unitName] = struct{}{}
				idx.symUnitCount[base] = len(multi)
			}
		}
	}
	for _, s := range modifiedSyms {
		idx.modifiedSyms[s] = struct{}{}
		idx.modifiedSyms[BaseSymbolName(s)] = struct{}{}
	}
	for _, f := range modifiedFiles {
		clean := cleanUnitName(f)
		idx.modifiedFiles[clean] = struct{}{}
		if dir := filepath.ToSlash(filepath.Dir(clean)); dir != "." && dir != "" {
			idx.modifiedSubdirs[dir] = struct{}{}
		}
	}
	return idx
}

func (idx *covFilterIndex) isModifiedSymbol(name string) bool {
	if _, ok := idx.modifiedSyms[name]; ok {
		return true
	}
	_, ok := idx.modifiedSyms[BaseSymbolName(name)]
	return ok
}

func addObjectUnitPCs(pcs map[uint64]struct{}, unit *backend.ObjectUnit) {
	// Include both coverage points and comparison interception points
	// because executor filters comparisons as well.
	for _, pc := range unit.PCs {
		pcs[pc] = struct{}{}
	}
	for _, pc := range unit.CMPs {
		pcs[pc] = struct{}{}
	}
}

func CoverageFilter(source *ReportGeneratorWrapper, covCfg mgrconfig.CovFilterCfg,
	strict bool) (map[uint64]struct{}, error) {
	if covCfg.Empty() {
		return nil, nil
	}
	rg, err := source.Get()
	if err != nil {
		return nil, err
	}
	var idx *covFilterIndex
	if covCfg.Unit != "" || len(covCfg.HeaderFunctions) > 0 || covCfg.IncludeHeaderInlines {
		idx = newCovFilterIndex(rg.Impl, nil, nil)
	}
	return coverageFilterWithIndex(rg.Impl, idx, covCfg, strict)
}

func coverageFilterWithIndex(rg *backend.Impl, idx *covFilterIndex, covCfg mgrconfig.CovFilterCfg,
	strict bool) (map[uint64]struct{}, error) {
	if covCfg.Empty() {
		return nil, nil
	}
	pcs := make(map[uint64]struct{})
	if covCfg.Unit != "" {
		covFilterAddUnit(pcs, idx, covCfg)
	} else {
		foreachSymbol := func(apply func(*backend.ObjectUnit)) {
			for _, sym := range rg.Symbols {
				apply(&sym.ObjectUnit)
			}
		}
		if err := covFilterAddFilter(pcs, covCfg.Functions, foreachSymbol, strict); err != nil {
			return nil, err
		}
	}
	if len(covCfg.HeaderFunctions) > 0 || covCfg.IncludeHeaderInlines {
		covFilterAddHeaderInlines(pcs, idx, covCfg)
	}
	foreachUnit := func(apply func(*backend.ObjectUnit)) {
		for _, unit := range rg.Units {
			apply(&unit.ObjectUnit)
		}
	}
	if err := covFilterAddFilter(pcs, covCfg.Files, foreachUnit, strict); err != nil {
		return nil, err
	}
	if err := covFilterAddRawPCs(pcs, covCfg.RawPCs); err != nil {
		return nil, err
	}
	return pcs, nil
}

func covFilterAddUnit(pcs map[uint64]struct{}, idx *covFilterIndex, covCfg mgrconfig.CovFilterCfg) {
	if idx == nil {
		return
	}
	unitName := cleanUnitName(covCfg.Unit)
	syms := idx.unitSyms[unitName]
	units := idx.unitsByName[unitName]
	if len(syms) == 0 && len(units) == 0 {
		return
	}

	wantFuncs := make(map[string]struct{}, len(covCfg.Functions))
	for _, fn := range covCfg.Functions {
		clean := strings.TrimSuffix(strings.TrimPrefix(fn, "^"), "$")
		if clean != "" {
			wantFuncs[clean] = struct{}{}
			wantFuncs[BaseSymbolName(clean)] = struct{}{}
		}
	}

	matchedHunkSyms := 0
	var changedInUnit []*backend.Symbol
	for _, sym := range syms {
		base := BaseSymbolName(sym.Name)
		_, matchExact := wantFuncs[sym.Name]
		_, matchBase := wantFuncs[base]
		if matchExact || matchBase {
			addObjectUnitPCs(pcs, &sym.ObjectUnit)
			matchedHunkSyms++
		}
		if idx.isModifiedSymbol(sym.Name) && idx.symUnitCount[base] <= 2 {
			changedInUnit = append(changedInUnit, sym)
		}
	}

	// Include binary-changed symbols in this unit to catch inlined static helpers,
	// while avoiding mass __LINE__-shift bystanders in large files.
	const (
		maxChangedWithHunks    = 8
		maxChangedWithoutHunks = 16
	)
	if len(changedInUnit) > 0 &&
		(len(changedInUnit) <= maxChangedWithHunks ||
			matchedHunkSyms == 0 && len(changedInUnit) <= maxChangedWithoutHunks) {
		for _, sym := range changedInUnit {
			addObjectUnitPCs(pcs, &sym.ObjectUnit)
		}
	}

	if len(pcs) == 0 && !IsHotCoreKernelUnit(unitName) {
		covFilterFallbackUnit(pcs, changedInUnit, units)
	}
}

func covFilterFallbackUnit(pcs map[uint64]struct{}, changedInUnit []*backend.Symbol, units []*backend.CompileUnit) {
	// When all hunk functions in a non-core unit were inlined into callers in the same unit,
	// include binary-changed symbols in this unit even on larger files (capped by PC budget)
	// so the modified unit never degrades to 0 PCs.
	if len(changedInUnit) > 0 {
		const maxInlinedCallerPCs = 4000
		changedPCs := 0
		for _, sym := range changedInUnit {
			changedPCs += len(sym.PCs)
		}
		if changedPCs <= maxInlinedCallerPCs {
			for _, sym := range changedInUnit {
				addObjectUnitPCs(pcs, &sym.ObjectUnit)
			}
			if len(pcs) > 0 {
				return
			}
		}
	}

	// Fall back to whole-unit PCs for small non-core modified units where no function symbol
	// or binary-changed symbol matched directly (e.g. patches touching ops/policy tables).
	totalUnitPCs := 0
	for _, u := range units {
		totalUnitPCs += len(u.PCs)
	}
	const maxFallbackUnitPCs = 1000
	if totalUnitPCs <= maxFallbackUnitPCs {
		for _, u := range units {
			addObjectUnitPCs(pcs, &u.ObjectUnit)
		}
	}
}

func covFilterAddHeaderInlines(pcs map[uint64]struct{}, idx *covFilterIndex, covCfg mgrconfig.CovFilterCfg) {
	if idx == nil {
		return
	}
	const maxHeaderFuncUnits = 8
	for _, fn := range covCfg.HeaderFunctions {
		base := BaseSymbolName(strings.TrimSuffix(strings.TrimPrefix(fn, "^"), "$"))
		if base == "" || idx.symUnitCount[base] > maxHeaderFuncUnits {
			continue
		}
		for _, sym := range idx.symsByBase[base] {
			if sym.Unit != nil && IsHotCoreKernelUnit(sym.Unit.Name) {
				continue
			}
			addObjectUnitPCs(pcs, &sym.ObjectUnit)
		}
	}
	if !covCfg.IncludeHeaderInlines || len(idx.modifiedSyms) == 0 {
		return
	}
	const (
		maxChangedPerCallerUnit = 4
		maxCallerSymPCs         = 400
		maxHeaderInlineSyms     = 200
	)
	var preferred, other []*backend.Symbol
	unitNames := slices.Sorted(maps.Keys(idx.unitSyms))
	for _, unitName := range unitNames {
		if _, directlyModified := idx.modifiedFiles[unitName]; directlyModified {
			continue
		}
		if IsHotCoreKernelUnit(unitName) {
			continue
		}
		var unitChanged []*backend.Symbol
		for _, sym := range idx.unitSyms[unitName] {
			base := BaseSymbolName(sym.Name)
			if idx.isModifiedSymbol(sym.Name) && idx.symUnitCount[base] == 1 {
				unitChanged = append(unitChanged, sym)
			}
		}
		if len(unitChanged) == 0 || len(unitChanged) > maxChangedPerCallerUnit {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(unitName))
		_, sameDir := idx.modifiedSubdirs[dir]
		for _, sym := range unitChanged {
			if len(sym.PCs) > maxCallerSymPCs {
				continue
			}
			if sameDir {
				preferred = append(preferred, sym)
			} else {
				other = append(other, sym)
			}
		}
	}
	added := 0
	for _, sym := range slices.Concat(preferred, other) {
		if added >= maxHeaderInlineSyms {
			break
		}
		addObjectUnitPCs(pcs, &sym.ObjectUnit)
		added++
	}
}

func exactMatchPattern(expr string) (string, bool) {
	if len(expr) < 2 || expr[0] != '^' || expr[len(expr)-1] != '$' {
		return "", false
	}
	// Check that trailing '$' is not escaped.
	backslashes := 0
	for i := len(expr) - 2; i >= 1 && expr[i] == '\\'; i-- {
		backslashes++
	}
	if backslashes%2 == 1 {
		return "", false
	}
	inner := expr[1 : len(expr)-1]
	var b strings.Builder
	b.Grow(len(inner))
	escaped := false
	for i := range len(inner) {
		ch := inner[i]
		if escaped {
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
				return "", false
			}
			b.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			if i+1 >= len(inner) {
				return "", false
			}
			escaped = true
			continue
		}
		switch ch {
		case '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$':
			return "", false
		default:
			b.WriteByte(ch)
		}
	}
	return b.String(), true
}

func covFilterAddFilter(pcs map[uint64]struct{}, filters []string, foreach func(func(*backend.ObjectUnit)),
	strict bool) error {
	if len(filters) == 0 {
		return nil
	}
	var exactOrder []string
	var exactSet map[string][]string
	var regexStrings []string
	for _, f := range filters {
		if lit, ok := exactMatchPattern(f); ok {
			if exactSet == nil {
				exactSet = make(map[string][]string)
			}
			if _, seen := exactSet[lit]; !seen {
				exactOrder = append(exactOrder, lit)
				exactSet[lit] = nil
			}
		} else {
			regexStrings = append(regexStrings, f)
		}
	}
	res, err := compileRegexps(regexStrings)
	if err != nil {
		return err
	}
	used := make(map[*regexp.Regexp][]string)
	foreach(func(unit *backend.ObjectUnit) {
		if matches, ok := exactSet[unit.Name]; ok {
			addObjectUnitPCs(pcs, unit)
			exactSet[unit.Name] = append(matches, unit.Name)
			return
		}
		for _, re := range res {
			if re.MatchString(unit.Name) {
				addObjectUnitPCs(pcs, unit)
				used[re] = append(used[re], unit.Name)
				break
			}
		}
	})
	logLevel := 0
	if len(filters) > 16 {
		logLevel = 1
	}
	matchedFilters := 0
	for _, lit := range exactOrder {
		matches := exactSet[lit]
		if len(matches) > 0 {
			matchedFilters++
		}
		log.Logf(logLevel, "coverage filter: ^%s$: %v", lit, matches)
	}
	for _, re := range res {
		slices.Sort(used[re])
		if len(used[re]) > 0 {
			matchedFilters++
		}
		log.Logf(logLevel, "coverage filter: %v: %v", re, used[re])
	}
	if len(filters) > 16 {
		log.Logf(0, "coverage filter matched %d/%d patterns (%d PCs)",
			matchedFilters, len(exactOrder)+len(res), len(pcs))
	}
	if strict && matchedFilters != len(exactOrder)+len(res) {
		return fmt.Errorf("some filters don't match anything")
	}
	return nil
}

func covFilterAddRawPCs(pcs map[uint64]struct{}, rawPCsFiles []string) error {
	re := regexp.MustCompile(`(0x[0-9a-f]+)(?:: (0x[0-9a-f]+))?`)
	for _, f := range rawPCsFiles {
		rawFile, err := os.Open(f)
		if err != nil {
			return fmt.Errorf("failed to open raw PCs file: %w", err)
		}
		defer rawFile.Close()
		s := bufio.NewScanner(rawFile)
		for s.Scan() {
			match := re.FindStringSubmatch(s.Text())
			if match == nil {
				return fmt.Errorf("bad line: %q", s.Text())
			}
			pc, err := strconv.ParseUint(match[1], 0, 64)
			if err != nil {
				return err
			}
			weight, err := strconv.ParseUint(match[2], 0, 32)
			if match[2] != "" && err != nil {
				return err
			}
			// If no weight is detected, set the weight to 0x1 by default.
			if match[2] == "" || weight < 1 {
				weight = 1
			}
			_ = weight // currently unused
			pcs[pc] = struct{}{}
		}
		if err := s.Err(); err != nil {
			return err
		}
	}
	return nil
}

func compileRegexps(regexpStrings []string) ([]*regexp.Regexp, error) {
	var regexps []*regexp.Regexp
	for _, rs := range regexpStrings {
		r, err := regexp.Compile(rs)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		regexps = append(regexps, r)
	}
	return regexps, nil
}

type CoverageFilters struct {
	Areas          []corpus.FocusArea
	ExecutorFilter map[uint64]struct{}
}

func PrepareCoverageFilters(source *ReportGeneratorWrapper, cfg *mgrconfig.Config,
	strict bool) (CoverageFilters, error) {
	var ret CoverageFilters
	needExecutorFilter := len(cfg.Experimental.FocusAreas) > 0
	var rg *backend.Impl
	var idx *covFilterIndex
	for _, area := range cfg.Experimental.FocusAreas {
		var pcs map[uint64]struct{}
		if !area.Filter.Empty() {
			if rg == nil {
				repGen, err := source.Get()
				if err != nil {
					return ret, err
				}
				rg = repGen.Impl
				idx = newCovFilterIndex(rg, cfg.Experimental.ModifiedSymbols, cfg.Experimental.ModifiedFiles)
			}
			var err error
			pcs, err = coverageFilterWithIndex(rg, idx, area.Filter, strict)
			if err != nil {
				return ret, err
			}
		}
		if area.Filter.Empty() {
			// An empty cover filter indicates that the user is interested in all the coverage.
			needExecutorFilter = false
		} else if len(pcs) == 0 {
			logLevel := 0
			if len(cfg.Experimental.FocusAreas) > 16 {
				logLevel = 1
			}
			log.Logf(logLevel, "focus area %q matched no PCs, skipping", area.Name)
			continue
		}
		// KCOV will point to the next instruction, so we need to adjust the map.
		covPCs := make(map[uint64]struct{}, len(pcs))
		for pc := range pcs {
			next := backend.NextInstructionPC(cfg.SysTarget, cfg.Type, pc)
			covPCs[next] = struct{}{}
		}
		ret.Areas = append(ret.Areas, corpus.FocusArea{
			Name:           area.Name,
			CoverPCs:       covPCs,
			Weight:         area.Weight,
			AdaptiveWeight: area.AdaptiveWeight,
		})
	}
	if len(cfg.Experimental.FocusAreas) > 0 && len(ret.Areas) == 0 {
		if strict {
			return ret, fmt.Errorf("none of the focus areas matched any PCs")
		}
		log.Logf(0, "none of the focus areas matched any PCs, falling back to full kernel coverage")
		ret.Areas = append(ret.Areas, corpus.FocusArea{Weight: 1.0})
		needExecutorFilter = false
	}
	if needExecutorFilter {
		ret.ExecutorFilter = map[uint64]struct{}{}
		for _, area := range ret.Areas {
			for pc := range area.CoverPCs {
				ret.ExecutorFilter[pc] = struct{}{}
			}
		}
	}
	return ret, nil
}
