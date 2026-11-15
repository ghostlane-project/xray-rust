// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

package zzmem

import (
	"strings"
	"testing"
)

const rollupFixture = `55d0c8a00000-7ffd3c3a5000 ---p 00000000 00:00 0                          [rollup]
Rss:               11520 kB
Pss:               10880 kB
Pss_Dirty:          7340 kB
Shared_Clean:       3100 kB
Shared_Dirty:          0 kB
Private_Clean:      1080 kB
Private_Dirty:      7340 kB
Referenced:        11520 kB
Anonymous:          7340 kB
LazyFree:              0 kB
AnonHugePages:      2048 kB
Swap:                  0 kB
`

const statusFixture = `Name:	olc-client
VmPeak:	  300000 kB
VmHWM:	   11900 kB
VmRSS:	   11520 kB
RssAnon:	    7340 kB
RssFile:	    4180 kB
RssShmem:	       0 kB
Threads:	9
`

const smapsFixture = `55d0c8a00000-55d0c9100000 r-xp 00000000 08:01 1234                       /opt/bin/olc-client
Size:               7168 kB
Rss:                3000 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:      3000 kB
Private_Dirty:         0 kB
Anonymous:             0 kB
55d0c9200000-55d0c9300000 rw-p 00700000 08:01 1234                       /opt/bin/olc-client
Size:               1024 kB
Rss:                 900 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:        20 kB
Private_Dirty:       880 kB
Anonymous:           880 kB
55d0c9400000-55d0c9800000 rw-p 00000000 00:00 0                          [heap]
Size:               4096 kB
Rss:                2500 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:      2500 kB
Anonymous:          2500 kB
7f0000000000-7f0004000000 rw-p 00000000 00:00 0
Size:              65536 kB
Rss:                 700 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:       700 kB
Anonymous:           700 kB
7f0010000000-7f0010200000 r-xp 00000000 08:01 99                          /usr/lib64/libc.so.6
Size:               2048 kB
Rss:                1000 kB
Shared_Clean:       1000 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Anonymous:             0 kB
`

func TestParseKB(t *testing.T) {
	r := ParseKB(rollupFixture)
	for k, want := range map[string]int64{"Rss": 11520, "Anonymous": 7340, "Private_Dirty": 7340, "Shared_Clean": 3100, "Private_Clean": 1080} {
		if r[k] != want {
			t.Errorf("rollup %s = %d, want %d", k, r[k], want)
		}
	}
	s := ParseKB(statusFixture)
	for k, want := range map[string]int64{"VmHWM": 11900, "RssAnon": 7340, "RssFile": 4180} {
		if s[k] != want {
			t.Errorf("status %s = %d, want %d", k, s[k], want)
		}
	}
	if s["Threads"] != 9 {
		t.Errorf("Threads = %d, want 9", s["Threads"])
	}
}

func TestParseMaps(t *testing.T) {
	maps := ParseMaps(smapsFixture)
	if len(maps) != 5 {
		t.Fatalf("%d mappings, want 5", len(maps))
	}
	if maps[2].Name != "[heap]" || maps[2].Rss != 2500 || maps[2].PrivateDirty != 2500 || maps[2].Perms != "rw-p" {
		t.Errorf("heap mapping parsed as %+v", maps[2])
	}
	if maps[3].Name != "" || maps[3].Size != 65536 {
		t.Errorf("anonymous mapping parsed as %+v", maps[3])
	}
	top := TopByRss(maps, 2)
	if len(top) != 2 || top[0].Rss != 3000 || top[1].Rss != 2500 {
		t.Errorf("top 2 = %+v", top)
	}
}

func TestCategories(t *testing.T) {
	cats := Categorize(ParseMaps(smapsFixture), "/opt/bin/olc-client")
	want := map[string][3]int64{ // rss, anonymous, private dirty
		"heap":        {2500, 2500, 2500},
		"anon":        {700, 700, 700},
		"exe-text":    {3000, 0, 0},
		"exe-data":    {900, 880, 880},
		"shared-libs": {1000, 0, 0},
	}
	for name, w := range want {
		c := cats[name]
		if got := [3]int64{c.Rss, c.Anonymous, c.PrivateDirty}; got != w {
			t.Errorf("category %s = %v, want %v", name, got, w)
		}
	}
}

func TestLine(t *testing.T) {
	snap := Snapshot{
		Rollup: ParseKB(rollupFixture), Status: ParseKB(statusFixture),
		Maps: ParseMaps(smapsFixture),
	}
	line := snap.Line("/opt/bin/olc-client", 3)
	for _, sub := range []string{"RssAnon=7340", "RssFile=4180", "Threads=9", "Private_Dirty=7340", "AnonHugePages=2048", "dirty(anon+file private dirty)=", "[heap]", "exe-text"} {
		if !strings.Contains(line, sub) {
			t.Errorf("line lacks %q: %s", sub, line)
		}
	}
	if strings.Contains(line, "\n") {
		t.Errorf("a snapshot is one line: %q", line)
	}
}
