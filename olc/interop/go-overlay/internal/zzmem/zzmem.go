//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

// Package zzmem reads a Linux process's memory the way the Rust client's
// memory audit needs it: the status fields, smaps_rollup and the smaps
// mappings, taken together at one moment and told in one log line. It is a
// test-harness helper (the gate and the engine's Rust tests log the line at
// the sample with the peak VmRSS); the line is not the apps' log contract.
package zzmem

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ParseKB reads "Name:   N kB" and "Name:   N" lines (status, smaps_rollup)
// into a map of the numbers; lines that are not of that shape are skipped.
func ParseKB(text string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.ContainsAny(name, " \t") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		if n, err := strconv.ParseInt(f[0], 10, 64); err == nil {
			out[name] = n
		}
	}
	return out
}

// Map is one mapping of /proc/<pid>/smaps, sizes in KiB.
type Map struct {
	Name, Perms string
	Size, Rss   int64

	SharedClean, SharedDirty, PrivateClean, PrivateDirty, Anonymous int64
}

// ParseMaps reads the text of /proc/<pid>/smaps.
func ParseMaps(text string) []Map {
	var maps []Map
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && strings.Contains(f[0], "-") && !strings.HasSuffix(f[0], ":") {
			m := Map{Perms: f[1]}
			if len(f) > 5 {
				m.Name = strings.Join(f[5:], " ")
			}
			maps = append(maps, m)
			continue
		}
		if len(maps) == 0 {
			continue
		}
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		g := strings.Fields(rest)
		if len(g) == 0 {
			continue
		}
		n, err := strconv.ParseInt(g[0], 10, 64)
		if err != nil {
			continue
		}
		m := &maps[len(maps)-1]
		switch name {
		case "Size":
			m.Size = n
		case "Rss":
			m.Rss = n
		case "Shared_Clean":
			m.SharedClean = n
		case "Shared_Dirty":
			m.SharedDirty = n
		case "Private_Clean":
			m.PrivateClean = n
		case "Private_Dirty":
			m.PrivateDirty = n
		case "Anonymous":
			m.Anonymous = n
		}
	}
	return maps
}

// TopByRss is the n mappings with the most resident memory, largest first.
func TopByRss(maps []Map, n int) []Map {
	out := append([]Map(nil), maps...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rss > out[j].Rss })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Sum is a category's totals, KiB.
type Sum struct{ Rss, Anonymous, PrivateDirty, SharedDirty int64 }

// CategoryOrder is the order the line tells the categories in.
var CategoryOrder = []string{"heap", "anon", "stack", "exe-text", "exe-ro", "exe-data", "shared-libs", "other"}

// Categorize sorts the mappings: [heap]; anon (no name: glibc arenas, thread
// stacks, bss, mmap'd buffers); stack; the binary's code (exe-text), its
// read-only data (exe-ro) and its writable data (exe-data); the shared
// libraries; the rest ([vdso], [vvar], ...). exe is the binary's path.
func Categorize(maps []Map, exe string) map[string]Sum {
	out := map[string]Sum{}
	for _, m := range maps {
		var c string
		switch {
		case m.Name == "[heap]":
			c = "heap"
		case m.Name == "":
			c = "anon"
		case strings.HasPrefix(m.Name, "[stack"):
			c = "stack"
		case exe != "" && strings.HasPrefix(m.Name, exe):
			switch {
			case strings.Contains(m.Perms, "x"):
				c = "exe-text"
			case strings.Contains(m.Perms, "w"):
				c = "exe-data"
			default:
				c = "exe-ro"
			}
		case strings.HasPrefix(m.Name, "/"):
			c = "shared-libs"
		default:
			c = "other"
		}
		s := out[c]
		s.Rss += m.Rss
		s.Anonymous += m.Anonymous
		s.PrivateDirty += m.PrivateDirty
		s.SharedDirty += m.SharedDirty
		out[c] = s
	}
	return out
}

// Snapshot is one process's memory at one moment.
type Snapshot struct {
	Status, Rollup map[string]int64
	Maps           []Map
}

// Take reads pid's status, smaps_rollup and smaps. Whatever cannot be read
// stays empty (the process may be gone).
func Take(pid int) Snapshot {
	read := func(name string) string {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
		if err != nil {
			return ""
		}
		return string(raw)
	}
	return Snapshot{
		Status: ParseKB(read("status")),
		Rollup: ParseKB(read("smaps_rollup")),
		Maps:   ParseMaps(read("smaps")),
	}
}

// Dirty is the Linux proxy for an iPhone's phys_footprint: the pages the
// process has written, private and shared, anonymous or file-backed
// (smaps_rollup's Private_Dirty plus Shared_Dirty), KiB.
func (s Snapshot) Dirty() int64 { return s.Rollup["Private_Dirty"] + s.Rollup["Shared_Dirty"] }

// Line is the snapshot in one line, for a test log: the status split, the
// rollup, the dirty measure, the categories and the top mappings by Rss.
func (s Snapshot) Line(exe string, top int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "VmRSS=%d RssAnon=%d RssFile=%d Threads=%d", s.Status["VmRSS"], s.Status["RssAnon"], s.Status["RssFile"], s.Status["Threads"])
	fmt.Fprintf(&b, " | rollup Rss=%d Anonymous=%d Private_Dirty=%d Shared_Dirty=%d Private_Clean=%d Shared_Clean=%d",
		s.Rollup["Rss"], s.Rollup["Anonymous"], s.Rollup["Private_Dirty"], s.Rollup["Shared_Dirty"], s.Rollup["Private_Clean"], s.Rollup["Shared_Clean"])
	fmt.Fprintf(&b, " | dirty(anon+file private dirty)=%d", s.Dirty())
	cats := Categorize(s.Maps, exe)
	b.WriteString(" | cats(rss/anon/pdirty):")
	for _, name := range CategoryOrder {
		if c, ok := cats[name]; ok {
			fmt.Fprintf(&b, " %s=%d/%d/%d", name, c.Rss, c.Anonymous, c.PrivateDirty)
		}
	}
	b.WriteString(" | top:")
	for _, m := range TopByRss(s.Maps, top) {
		name := m.Name
		if name == "" {
			name = "anon"
		}
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		fmt.Fprintf(&b, " %s[%s size=%d rss=%d anon=%d pdirty=%d]", name, m.Perms, m.Size, m.Rss, m.Anonymous, m.PrivateDirty)
	}
	return b.String()
}

// Peak keeps the snapshot taken at the highest VmRSS seen.
type Peak struct {
	Snap  Snapshot
	maxKB int64
}

// Observe takes a snapshot of pid when its VmRSS is a new peak and says
// whether it was. The smaps read is only paid at a new peak.
func (p *Peak) Observe(pid int, rssKB int64) bool {
	if rssKB <= p.maxKB {
		return false
	}
	p.maxKB = rssKB
	p.Snap = Take(pid)
	return true
}
