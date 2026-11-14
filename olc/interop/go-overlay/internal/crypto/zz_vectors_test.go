//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// Golden vectors for the Rust port (olc/interop in the xray-rust fork). An
// overlay file: regen.sh copies it into a clean checkout of the pin.

package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/zzvectors"
)

// The lane AADs, as the packages that own them spell them
// (internal/muxconn/conn.go:73-74, internal/tunnelcore/core.go:26); the
// muxconn and tunnelcore generators write those constants themselves.
const (
	zzDataAAD    = "olcrtc/muxconn/v2/data"
	zzControlAAD = "olcrtc/muxconn/v2/control"
	zzUDPAAD     = "olcrtc/udp/v1"
)

var zzLaneAAD = map[string]string{"data": zzDataAAD, "control": zzControlAAD, "udp": zzUDPAAD}

var zzLaneOrder = []string{"data", "control", "udp"}

func zzPSK() []byte {
	s := sha256.Sum256([]byte("olcrtc rust port: golden vectors"))
	return s[:]
}

func zzPrefix(seed byte) [noncePrefixSize]byte {
	var p [noncePrefixSize]byte
	for i := range p {
		p[i] = seed + byte(i)*17
	}
	return p
}

func zzKeys(t *testing.T, psk []byte, role Role) *KeySet {
	t.Helper()
	k, err := NewKeySet(psk, role)
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return k
}

// zzSeal seals one record the way SealInto does (sealWith, chacha.go:243-262)
// from a lane state whose prefix and counter are fixed instead of random.
func zzSeal(k *KeySet, aad string, prefix [noncePrefixSize]byte, counterBefore uint64, plaintext []byte) ([]byte, error) {
	state := &sealState{aead: k.sendAEAD, prefix: prefix}
	state.counter.Store(counterBefore)
	return sealWith(state, nil, plaintext, []byte(aad))
}

func zzMustSeal(t *testing.T, k *KeySet, lane string, prefix [noncePrefixSize]byte, counter uint64, plaintext []byte) []byte {
	t.Helper()
	record, err := zzSeal(k, zzLaneAAD[lane], prefix, counter-1, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return record
}

func zzVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrRecordTooShort):
		return "too_short"
	case errors.Is(err, ErrBadRecordMagic):
		return "bad_magic"
	case errors.Is(err, ErrInvalidCounter):
		return "invalid_counter"
	case errors.Is(err, ErrAuthentication):
		return "auth"
	case errors.Is(err, ErrReplayDuplicate):
		return "duplicate"
	case errors.Is(err, ErrReplayTooOld):
		return "too_old"
	case errors.Is(err, ErrCounterExhausted):
		return "counter_exhausted"
	case errors.Is(err, ErrInvalidKeySize):
		return "invalid_key_size"
	default:
		return "other: " + err.Error()
	}
}

type zzKeyCase struct {
	PSK            string `json:"psk"`
	ClientToServer string `json:"client_to_server"`
	ServerToClient string `json:"server_to_client"`
}

type zzBadPSK struct {
	Len     int    `json:"len"`
	Verdict string `json:"verdict"`
}

type zzKeyFile struct {
	ClientToServerLabel string      `json:"client_to_server_label"`
	ServerToClientLabel string      `json:"server_to_client_label"`
	RecordMagic         string      `json:"record_magic"`
	NoncePrefixSize     int         `json:"nonce_prefix_size"`
	RecordHeaderSize    int         `json:"record_header_size"`
	WireOverhead        int         `json:"wire_overhead"`
	ReplayWindowSize    int         `json:"replay_window_size"`
	MaxReplaySenders    int         `json:"max_replay_senders"`
	Keys                []zzKeyCase `json:"keys"`
	InvalidPSKLengths   []zzBadPSK  `json:"invalid_psk_lengths"`
}

type zzSealCase struct {
	Name          string                 `json:"name"`
	Role          string                 `json:"role"`
	Lane          string                 `json:"lane"`
	AAD           string                 `json:"aad"`
	Prefix        string                 `json:"prefix"`
	CounterBefore uint64                 `json:"counter_before"`
	Plaintext     string                 `json:"plaintext,omitempty"`
	PlainPattern  *zzvectors.PatternSpec `json:"plaintext_pattern,omitempty"`
	Verdict       string                 `json:"verdict"`
	Record        string                 `json:"record,omitempty"`
	RecordSHA256  string                 `json:"record_sha256,omitempty"`
	RecordLen     int                    `json:"record_len"`
}

type zzSequenceCase struct {
	Name      string   `json:"name"`
	Role      string   `json:"role"`
	Lane      string   `json:"lane"`
	Prefix    string   `json:"prefix"`
	Plaintext []string `json:"plaintexts"`
	Records   []string `json:"records"`
}

type zzSealFile struct {
	PSK       string           `json:"psk"`
	Cases     []zzSealCase     `json:"cases"`
	Sequences []zzSequenceCase `json:"sequences"`
}

type zzOpenStep struct {
	Note    string `json:"note,omitempty"`
	Lane    string `json:"lane"`
	Record  string `json:"record"`
	Verdict string `json:"verdict"`
	Plain   string `json:"plain,omitempty"`
}

type zzReorder struct {
	Skipped uint64 `json:"skipped"`
	Late    uint64 `json:"late"`
}

type zzOpenSequence struct {
	Name     string               `json:"name"`
	Receiver string               `json:"receiver"`
	Steps    []zzOpenStep         `json:"steps"`
	Reorder  map[string]zzReorder `json:"reorder"`
}

type zzOpenFile struct {
	PSK       string           `json:"psk"`
	Sequences []zzOpenSequence `json:"sequences"`
}

// zzOpener runs records through one receiving KeySet in order and keeps the
// verdict the Go code gave each.
type zzOpener struct {
	keys *KeySet
	seq  zzOpenSequence
}

func (o *zzOpener) open(note, lane string, record []byte) {
	plain, err := o.keys.Open(record, []byte(zzLaneAAD[lane]))
	step := zzOpenStep{Note: note, Lane: lane, Record: zzvectors.Hex(record), Verdict: zzVerdict(err)}
	if err == nil {
		step.Plain = zzvectors.Hex(plain)
	}
	o.seq.Steps = append(o.seq.Steps, step)
}

func (o *zzOpener) finish() zzOpenSequence {
	o.seq.Reorder = map[string]zzReorder{}
	for _, lane := range zzLaneOrder {
		stats := o.keys.ReorderStats([]byte(zzLaneAAD[lane]))
		o.seq.Reorder[lane] = zzReorder{Skipped: stats.Skipped, Late: stats.Late}
	}
	return o.seq
}

func TestZZVectors(t *testing.T) {
	t.Run("keys", zzKeysFile)
	t.Run("seal", zzSealVectors)
	t.Run("open", zzOpenVectors)
}

func zzKeysFile(t *testing.T) {
	psks := [][]byte{make([]byte, 32), bytes.Repeat([]byte{0xff}, 32), zzvectors.Pattern(32, 0), zzPSK()}
	file := zzKeyFile{
		ClientToServerLabel: clientToServerLabel,
		ServerToClientLabel: serverToClientLabel,
		RecordMagic:         recordMagic,
		NoncePrefixSize:     noncePrefixSize,
		RecordHeaderSize:    recordHeaderSize,
		WireOverhead:        WireOverhead,
		ReplayWindowSize:    replayWindowSize,
		MaxReplaySenders:    maxReplaySenders,
	}
	for _, psk := range psks {
		c2s, err := deriveKey(psk, clientToServerLabel)
		if err != nil {
			t.Fatal(err)
		}
		s2c, err := deriveKey(psk, serverToClientLabel)
		if err != nil {
			t.Fatal(err)
		}
		file.Keys = append(file.Keys, zzKeyCase{
			PSK: zzvectors.Hex(psk), ClientToServer: zzvectors.Hex(c2s[:]), ServerToClient: zzvectors.Hex(s2c[:]),
		})
	}
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, err := NewKeySet(make([]byte, n), Client)
		file.InvalidPSKLengths = append(file.InvalidPSKLengths, zzBadPSK{Len: n, Verdict: zzVerdict(err)})
	}
	zzvectors.Write(t, "crypto/keys.json", "internal/crypto/zz_vectors_test.go zzKeysFile",
		[]string{"internal/crypto/chacha.go:30-45", "internal/crypto/chacha.go:155-177"}, file)
}

func zzSealVectors(t *testing.T) {
	psk := zzPSK()
	sides := []struct {
		name string
		keys *KeySet
	}{{"client", zzKeys(t, psk, Client)}, {"server", zzKeys(t, psk, Server)}}
	file := zzSealFile{PSK: zzvectors.Hex(psk)}
	add := func(name, role string, keys *KeySet, lane string, prefix [noncePrefixSize]byte, before uint64, plain []byte, pattern *zzvectors.PatternSpec) {
		record, err := zzSeal(keys, zzLaneAAD[lane], prefix, before, plain)
		c := zzSealCase{
			Name: name, Role: role, Lane: lane, AAD: zzLaneAAD[lane], Prefix: zzvectors.Hex(prefix[:]),
			CounterBefore: before, PlainPattern: pattern, Verdict: zzVerdict(err), RecordLen: len(record),
		}
		if pattern == nil {
			c.Plaintext = zzvectors.Hex(plain)
		}
		if err == nil {
			if len(record) > zzvectors.LargeOutput {
				c.RecordSHA256 = zzvectors.Sum(record)
			} else {
				c.Record = zzvectors.Hex(record)
			}
		}
		file.Cases = append(file.Cases, c)
	}
	counters := []uint64{0, 1, 254, 255, 1<<32 - 1, math.MaxUint64 - 1}
	for si, side := range sides {
		for li, lane := range zzLaneOrder {
			for ci, before := range counters {
				seed := byte(si*64 + li*16 + ci)
				plain := zzvectors.Pattern(5+ci*7, seed)
				add("counter", side.name, side.keys, lane, zzPrefix(seed), before, plain, nil)
			}
		}
	}
	for _, n := range []int{0, 1, 15, 16, 17, 63, 64, 65, 1200, 12244, 32776} {
		spec := &zzvectors.PatternSpec{Len: n, Seed: byte(n)}
		add("size", "client", sides[0].keys, "data", zzPrefix(0xa5), 0, zzvectors.Pattern(n, byte(n)), spec)
	}
	// The counter never wraps: a lane at MaxUint64 seals nothing (chacha.go:271-281).
	add("exhausted", "client", sides[0].keys, "data", zzPrefix(1), math.MaxUint64, []byte("x"), nil)

	// The public path: SealInto numbers a lane's records from 1, one counter per
	// lane (chacha.go:205-240). The prefix is the only thing fixed here.
	for li, lane := range zzLaneOrder {
		keys := zzKeys(t, psk, Client)
		prefix := zzPrefix(byte(0x40 + li))
		keys.lanes[zzLaneAAD[lane]] = &sealState{aead: keys.sendAEAD, prefix: prefix}
		seq := zzSequenceCase{Name: "seal_into", Role: "client", Lane: lane, Prefix: zzvectors.Hex(prefix[:])}
		for i := range 3 {
			plain := zzvectors.Pattern(3+i, byte(i))
			record, err := keys.SealInto(nil, plain, []byte(zzLaneAAD[lane]))
			if err != nil {
				t.Fatal(err)
			}
			seq.Plaintext = append(seq.Plaintext, zzvectors.Hex(plain))
			seq.Records = append(seq.Records, zzvectors.Hex(record))
		}
		file.Sequences = append(file.Sequences, seq)
	}
	zzvectors.Write(t, "crypto/seal.json", "internal/crypto/zz_vectors_test.go zzSealVectors",
		[]string{"internal/crypto/chacha.go:205-281"}, file)
}

func zzOpenVectors(t *testing.T) {
	psk := zzPSK()
	client := zzKeys(t, psk, Client)
	file := zzOpenFile{PSK: zzvectors.Hex(psk)}
	newOpener := func(name string) *zzOpener {
		return &zzOpener{keys: zzKeys(t, psk, Server), seq: zzOpenSequence{Name: name, Receiver: "server"}}
	}
	a, b := zzPrefix(0x11), zzPrefix(0x22)
	seal := func(lane string, prefix [noncePrefixSize]byte, counter uint64) []byte {
		return zzMustSeal(t, client, lane, prefix, counter, zzvectors.Pattern(int(counter%9), byte(counter)))
	}

	o := newOpener("duplicate")
	o.open("first", "data", seal("data", a, 1))
	o.open("the same record again", "data", seal("data", a, 1))
	o.open("next", "data", seal("data", a, 2))
	file.Sequences = append(file.Sequences, o.finish())

	o = newOpener("lanes_are_independent")
	o.open("", "data", seal("data", a, 5))
	o.open("control counts from its own 1", "control", seal("control", a, 1))
	o.open("late on data", "data", seal("data", a, 4))
	o.open("", "control", seal("control", a, 1))
	o.open("", "udp", seal("udp", a, 1))
	o.open("a control record far ahead", "control", seal("control", a, 1000))
	o.open("does not age out the data backlog", "data", seal("data", a, 3))
	file.Sequences = append(file.Sequences, o.finish())

	o = newOpener("window_edges")
	o.open("", "data", seal("data", a, 100))
	o.open("age 63 is inside", "data", seal("data", a, 37))
	o.open("age 64 is too old", "data", seal("data", a, 36))
	o.open("", "data", seal("data", a, 100))
	o.open("a jump of 64 resets the window", "data", seal("data", a, 164))
	o.open("", "data", seal("data", a, 101))
	o.open("", "data", seal("data", a, 100))
	o.open("a jump of 63 keeps it", "data", seal("data", a, 227))
	o.open("", "data", seal("data", a, 164))
	o.open("", "data", seal("data", a, 163))
	file.Sequences = append(file.Sequences, o.finish())

	o = newOpener("malformed")
	good := seal("data", a, 7)
	for _, n := range []int{0, 1, WireOverhead - 1} {
		o.open("short", "data", good[:n])
	}
	badMagic := bytes.Clone(good)
	badMagic[0] ^= 0xff
	o.open("bad magic", "data", badMagic)
	zeroCounter := bytes.Clone(good)
	binary.BigEndian.PutUint64(zeroCounter[4:12], 0)
	o.open("counter zero", "data", zeroCounter)
	o.open("truncated tag", "data", good[:len(good)-1])
	flipped := bytes.Clone(good)
	flipped[len(flipped)-20] ^= 1
	o.open("flipped ciphertext", "data", flipped)
	o.open("the data record on the control lane", "control", good)
	reflected := zzMustSeal(t, zzKeys(t, psk, Server), "data", a, 8, []byte("reflected"))
	o.open("a server record back at the server", "data", reflected)
	o.open("exactly the overhead, empty plaintext", "data", seal("data", a, 9))
	o.open("the good record, after all that", "data", good)
	file.Sequences = append(file.Sequences, o.finish())

	o = newOpener("failed_open_leaves_state")
	tampered := seal("data", a, 10)
	tampered[len(tampered)-1] ^= 1
	o.open("tampered", "data", tampered)
	o.open("the same counter, intact", "data", seal("data", a, 10))
	far := seal("data", a, 500)
	far[len(far)-1] ^= 1
	o.open("tampered far ahead", "data", far)
	o.open("still inside the window", "data", seal("data", a, 9))
	file.Sequences = append(file.Sequences, o.finish())

	o = newOpener("sender_prefixes")
	o.open("", "data", seal("data", a, 1))
	o.open("another sender", "data", seal("data", b, 1))
	o.open("", "data", seal("data", a, 1))
	o.open("", "data", seal("data", b, 2))
	file.Sequences = append(file.Sequences, o.finish())

	// TestReplayStateUsesBoundedLRU, as a sequence: maxReplaySenders + 1
	// senders, then the evicted first one and the newest one again.
	o = newOpener("bounded_lru")
	lruPrefix := func(i int) [noncePrefixSize]byte {
		var p [noncePrefixSize]byte
		binary.BigEndian.PutUint64(p[noncePrefixSize-8:], uint64(i))
		return p
	}
	for i := 0; i <= maxReplaySenders; i++ {
		o.open("", "data", zzMustSeal(t, client, "data", lruPrefix(i), 1, nil))
	}
	o.open("the least recently used sender was forgotten", "data", zzMustSeal(t, client, "data", lruPrefix(0), 1, nil))
	o.open("the newest sender was kept", "data", zzMustSeal(t, client, "data", lruPrefix(maxReplaySenders), 1, nil))
	o.open("re-adding the first evicted the second", "data", zzMustSeal(t, client, "data", lruPrefix(1), 1, nil))
	file.Sequences = append(file.Sequences, o.finish())

	zzvectors.Write(t, "crypto/open.json", "internal/crypto/zz_vectors_test.go zzOpenVectors",
		[]string{"internal/crypto/chacha.go:283-382"}, file)
}
