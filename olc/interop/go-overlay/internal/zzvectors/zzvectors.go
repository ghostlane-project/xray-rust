//go:build olcrtc_interop

// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.

// Package zzvectors writes the golden vectors the Rust port of the olcRTC
// client is tested against. It is not part of the engine: olc/interop in the
// xray-rust fork copies it, with the zz_vectors_test.go generators, into a
// clean checkout of the pinned engine and runs them there (regen.sh). Nothing
// here is random or reads the clock, so two runs write the same bytes.
package zzvectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Pin is the engine commit the vectors are generated at.
const Pin = "2d4266af3947f4d9940efafb0d5aabb6207f6659"

// File is the envelope of every vector file.
type File struct {
	Pin       string   `json:"pin"`
	Generator string   `json:"generator"`
	Sources   []string `json:"sources"`
	Cases     any      `json:"cases"`
}

// Write stores cases as <OLC_VECTORS_OUT>/<name>. The test is skipped when the
// variable is unset, so a plain `go test -tags olcrtc_interop` is unaffected.
func Write(t testing.TB, name, generator string, sources []string, cases any) {
	t.Helper()
	dir := os.Getenv("OLC_VECTORS_OUT")
	if dir == "" {
		t.Skip("OLC_VECTORS_OUT is not set")
	}
	body, err := json.MarshalIndent(File{Pin: Pin, Generator: generator, Sources: sources, Cases: cases}, "", " ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	body = append(body, '\n')
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Hex is lowercase hex.
func Hex(b []byte) string { return hex.EncodeToString(b) }

// Sum is the lowercase hex SHA-256 of b, stored instead of b when b is large.
func Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Pattern returns n deterministic bytes: byte i is (i*31 + seed) mod 251.
// The Rust tests rebuild large inputs from it instead of storing them.
func Pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31 + int(seed)) % 251)
	}
	return out
}

// PatternSpec names a Pattern input in a vector file.
type PatternSpec struct {
	Len  int  `json:"len"`
	Seed byte `json:"seed"`
}

// MustHex decodes a hex literal of the generator itself.
func MustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex literal %q: %v", s, err)
	}
	return b
}

// LargeOutput is the size above which a generator stores an output's length
// and SHA-256 instead of its bytes.
const LargeOutput = 4096
