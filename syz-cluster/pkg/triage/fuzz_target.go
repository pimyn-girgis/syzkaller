// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"fmt"
	"regexp"
	"slices"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

func SelectFuzzConfigs(series *api.Series, targets []*api.FuzzTriageTarget) []*api.KernelFuzzConfig {
	ret := selectByPaths(targets, series.ModifiedFiles())
	// Large stable RCs touch many subsystems across the kernel; include the unfocused fallback
	// so the main campaign runs unfocused while retaining matched corpora and priority targets.
	if series.IsStableRC() && len(series.Patches) > api.MaxRCFocusedPatches {
		return append(ret, defaultTargets(targets)...)
	}
	if len(ret) > 0 {
		return ret
	}
	return defaultTargets(targets)
}

func filterTargets(targets []*api.FuzzTriageTarget, match func(*api.FuzzTriageTarget) bool) []*api.KernelFuzzConfig {
	var ret []*api.KernelFuzzConfig
	for _, t := range targets {
		if match(t) {
			ret = append(ret, expandCampaigns(t)...)
		}
	}
	return ret
}

func defaultTargets(targets []*api.FuzzTriageTarget) []*api.KernelFuzzConfig {
	return filterTargets(targets, func(t *api.FuzzTriageTarget) bool {
		return len(t.PathRegexps) == 0
	})
}

func selectByPaths(targets []*api.FuzzTriageTarget, files []string) []*api.KernelFuzzConfig {
	return filterTargets(targets, func(t *api.FuzzTriageTarget) bool {
		return matchesPaths(t.PathRegexps, t.ExcludePathRegexps, files)
	})
}

func matchesPaths(regexps, excludeRegexps, modifiedFiles []string) bool {
	if len(regexps) == 0 || len(modifiedFiles) == 0 {
		return false
	}
	include := compileRegexps(regexps)
	exclude := compileRegexps(excludeRegexps)
	for _, file := range modifiedFiles {
		if matchesAny(include, file) && !matchesAny(exclude, file) {
			return true
		}
	}
	return false
}

func compileRegexps(regexps []string) []*regexp.Regexp {
	var ret []*regexp.Regexp
	for _, r := range regexps {
		ret = append(ret, regexp.MustCompile(r))
	}
	return ret
}

func matchesAny(regexps []*regexp.Regexp, str string) bool {
	for _, re := range regexps {
		if re.MatchString(str) {
			return true
		}
	}
	return false
}

func expandCampaigns(config *api.FuzzTriageTarget) []*api.KernelFuzzConfig {
	var ret []*api.KernelFuzzConfig
	for _, campaign := range config.Campaigns {
		c := *campaign
		if c.Focus == "" {
			c.Focus = config.Focus
		}
		if c.CorpusURL == "" {
			c.CorpusURL = config.CorpusURL
		}
		c.Priority = c.Priority || config.Priority
		if c.Priority {
			if len(c.PathRegexps) == 0 {
				c.PathRegexps = config.PathRegexps
			}
			if len(c.ExcludePathRegexps) == 0 {
				c.ExcludePathRegexps = config.ExcludePathRegexps
			}
		}
		ret = append(ret, &c)
	}
	return ret
}

type MergedFuzzConfig struct {
	KernelConfig string
	Track        string
	FuzzConfigs  []*api.FuzzConfig
}

func MergeKernelFuzzConfigs(configs []*api.KernelFuzzConfig) []*MergedFuzzConfig {
	type groupKey struct {
		config     string
		track      string
		bugTitleRe string
	}
	groups := map[groupKey][]*api.KernelFuzzConfig{}
	var orderedKeys []groupKey
	for _, config := range configs {
		// Some of the different fuzz configs may still be merged together,
		// e.g. if they only differ in the syscall lists and corpuses.
		key := groupKey{config.KernelConfig, config.Track, config.BugTitleRe}
		if _, ok := groups[key]; !ok {
			orderedKeys = append(orderedKeys, key)
		}
		groups[key] = append(groups[key], config)
	}
	var ret []*MergedFuzzConfig
	for _, key := range orderedKeys {
		// TODO: is there way to auto-generate a prefix?
		ret = append(ret, &MergedFuzzConfig{
			KernelConfig: key.config,
			Track:        key.track,
			FuzzConfigs:  mergeCampaignGroup(groups[key]),
		})
	}
	return ret
}

func mergeCampaignGroup(configs []*api.KernelFuzzConfig) []*api.FuzzConfig {
	mainCfg := mergeFuzzConfigs(configs)
	if len(mainCfg.Focus) > 0 {
		return []*api.FuzzConfig{mainCfg}
	}
	// When a series broadens to an unfocused campaign (e.g. on large stable/LTS RCs),
	// also emit dedicated force-focused campaigns for matched high-priority subsystems
	// (such as KVM and networking) sharing the same base/patched kernel builds.
	var (
		priorityOrder []string
		byFocus       = map[string][]*api.KernelFuzzConfig{}
	)
	for _, cfg := range configs {
		if !cfg.Priority || cfg.Focus == "" {
			continue
		}
		if _, ok := byFocus[cfg.Focus]; !ok {
			priorityOrder = append(priorityOrder, cfg.Focus)
		}
		byFocus[cfg.Focus] = append(byFocus[cfg.Focus], cfg)
	}
	var ret []*api.FuzzConfig
	for _, focus := range priorityOrder {
		prioCfg := mergeFuzzConfigs(byFocus[focus])
		prioCfg.Label = fmt.Sprintf("Fuzz (%s)", focus)
		var paths, excludePaths []string
		for _, cfg := range byFocus[focus] {
			paths = append(paths, cfg.PathRegexps...)
			excludePaths = append(excludePaths, cfg.ExcludePathRegexps...)
		}
		if len(paths) > 0 {
			prioCfg.FocusPaths = unique(paths)
		}
		if len(excludePaths) > 0 {
			prioCfg.ExcludeFocusPaths = unique(excludePaths)
		}
		ret = append(ret, prioCfg)
	}
	ret = append(ret, mainCfg)
	return ret
}

func mergeFuzzConfigs(configs []*api.KernelFuzzConfig) *api.FuzzConfig {
	var ret api.FuzzConfig
	for _, config := range configs {
		ret.Focus = append(ret.Focus, config.Focus)
		if config.CorpusURL != "" {
			ret.CorpusURLs = append(ret.CorpusURLs, config.CorpusURL)
		}
		ret.SkipCoverCheck = ret.SkipCoverCheck || config.SkipCoverCheck
		// Must be the same.
		ret.BugTitleRe = config.BugTitleRe
	}
	if slices.Contains(ret.Focus, "") {
		// If there's at least one unfocused target,
		// we fuzz everything this way.
		ret.Focus = nil
	} else {
		ret.Focus = unique(ret.Focus)
	}
	ret.CorpusURLs = unique(ret.CorpusURLs)
	return &ret
}

func unique(list []string) []string {
	list = slices.Clone(list)
	slices.Sort(list)
	return slices.Compact(list)
}
