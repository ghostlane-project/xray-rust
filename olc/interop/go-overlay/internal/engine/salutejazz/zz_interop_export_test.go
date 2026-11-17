// Copyright 2026 the Ghostlane authors. Licensed under the Apache License 2.0.
//
// An overlay file (olc/interop in the xray-rust fork): what the Rust interop
// tests (zz_rust_test.go) take from the fake SFU beyond export_test.go. The
// Rust client is a child process, so it joins with the room's credentials
// rather than through FakeRoom.Join, and the tests read the participants the
// fake admitted to tell its identity from the server's.

package salutejazz

import (
	"fmt"
	"slices"
	"time"
)

// The room FakeRoom.Join names: its code and its password.
const (
	FakeRoomCode     = "abc123"
	FakeRoomPassword = "passw0rd"
)

// URL is the connector's ws:// URL.
func (r *FakeRoom) URL() string { return r.url }

// Identities is every participant in the fake now, in the order it admitted
// them: one whose socket closed has left, one that joined again is listed
// under its new identity.
func (r *FakeRoom) Identities() []string {
	peers := r.fake.snapshot()
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.id)
	}
	return out
}

// SawAnswer and SawPublisherOffer say whether a client answered the
// subscriber offer and made a publisher offer.
func (r *FakeRoom) SawAnswer() bool { return r.fake.sawAnswer() }

// SawPublisherOffer: see SawAnswer.
func (r *FakeRoom) SawPublisherOffer() bool { return r.fake.sawPublisherOffer() }

// Joins is the payload of every join frame the fake saw, and the group id
// each carried (the capture has none).
func (r *FakeRoom) Joins() (payloads, groups []string) {
	for _, j := range r.fake.joins() {
		payloads = append(payloads, j.payload)
		groups = append(groups, j.group)
	}
	return payloads, groups
}

// ClientCandidates is every candidate a client trickled: the peer connection
// it named and the ICE username fragment it carried.
func (r *FakeRoom) ClientCandidates() (targets, ufrags []string) {
	for _, c := range r.fake.clientICE() {
		targets = append(targets, c.target)
		ufrags = append(ufrags, c.ufrag)
	}
	return targets, ufrags
}

// How DropAll waits: dropRelaySettle for a relay already past the held gate
// to finish (one packet handed to pion, microseconds), dropLeaveWithin for the
// fake to let go of everyone it dropped (its serve loop closes the peer
// connections and leaves at once; a few milliseconds on the box).
const (
	dropRelaySettle = 20 * time.Millisecond
	dropLeaveWithin = 10 * time.Second
)

// DropAll closes every fake-side socket without a close frame, the way a dead
// link ends a session, and returns once every participant it dropped has left
// the fake. The relay is held from just before the drop until then.
//
// Without the hold the fake races itself: its serve loop tears a dropped
// participant down (closePeerConnections, then leave) while its relay still
// delivers what the other side publishes, and a channel whose association has
// just closed still reads open, so deliver's Send fails and the fake records
// "deliver: sending payload data in non-established state: state=Closed"
// (fakeconnector_test.go, deliver) at 1-3 ms after the drop. That is the
// fake's, not the client's: the engine's own Go client trips it as often as
// the Rust client (R5, p3/m4-rtc.md). Once the dropped have left, what was
// held goes on, each channel's in its order, to whoever is then in the room.
func (r *FakeRoom) DropAll() error {
	release := r.fake.holdForward()
	defer release()
	time.Sleep(dropRelaySettle)
	dropped := r.Identities()
	r.fake.dropAll()
	deadline := time.Now().Add(dropLeaveWithin)
	for {
		ids := r.Identities()
		if !slices.ContainsFunc(dropped, func(id string) bool { return slices.Contains(ids, id) }) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the fake still lists %v of the dropped %v after %s", ids, dropped, dropLeaveWithin)
		}
		time.Sleep(time.Millisecond)
	}
}

// Swallow makes the relay drop every packet under topic.
func (r *FakeRoom) Swallow(topic string) { r.fake.swallow(topic) }

// FramesFrom is how many packets identity has published under topic.
func (r *FakeRoom) FramesFrom(identity, topic string) int { return r.fake.framesFrom(identity, topic) }

// Shutdown ends every participant: sockets, then peer connections. The
// connector itself stays up until the test ends.
func (r *FakeRoom) Shutdown() { r.fake.shutdown() }
