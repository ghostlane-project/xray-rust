# h2 0.4.20: Go's stream WINDOW_UPDATE policy, Xray's MASQUE client, Go's request headers and the read side's memory

Source: the complete unchanged-version crates.io `h2` **0.4.20** archive,
SHA256 `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118`.
Upstream licenses and the published lockfile remain intact. `XRAY-PATCH.diff`
reconstructs the local source from that archive with zero fuzz. Run
`scripts/check-vendored-sources.sh` to verify the archive, exact reconstruction,
and the library tests from an isolated copy.

## Stream window update threshold

`client::Builder::stream_window_update_threshold(size)` makes a stream's
WINDOW_UPDATE due once `size` bytes of released capacity have accumulated, or
once the update would at least double the window the peer sees. This is the
policy of Go's `x/net/http2` (`inflow.add`, `inflowMinRefresh` = 4 KiB).

Upstream waits until released capacity reaches half of the remaining window.
With a reader that keeps up, that returns about a third of the initial window
at a time: 1.4 MB of a 4 MiB window. At an added 113 ms the sender then runs
short of credit while each update crosses the link, and XHTTP H2 downloads
measured 28% slower than Go's client (`docs/issue28-client-comparison.md`).

The XHTTP H2 client sets a sixteenth of its opening stream window, at least
4 KiB: an update for every read cost a fast download 16% of its throughput.
Connection-level updates, the server, and every caller that leaves the option
unset keep upstream behavior. Unit tests in
`proto/streams/flow_control.rs` cover the threshold, the doubling rule and the
unchanged default.

## Waiting for the server's SETTINGS

`client::SendRequest::poll_remote_settings` is ready once the server's first
SETTINGS frame has been applied, or fails once the connection did first.
Xray-core's MASQUE HTTP/2 client sends its extended CONNECT only after that
frame and refuses a server that did not enable the protocol in it; before
it, `is_extended_connect_protocol_enabled` reports `false` for any server.
A waiting task is woken by that frame, a connection error, GOAWAY or EOF.

## Xray-core's MASQUE request header block

Two `client::Builder` options let the MASQUE client write the header block
Xray-core v26.10.31's own HTTP/2 client writes:

- `send_header_table_size_limit(size)` caps the HPACK encoder's dynamic table
  below what the server allows, announcing the smaller table in the first
  header block, as Go's `hpack.Encoder.SetMaxDynamicTableSizeLimit`. Xray
  sets zero: a size update, then every field without indexing.
- `authority_after_method(true)` writes `:authority` right after `:method`,
  before `:scheme` and `:path`, the order of Chrome and of Go's writers.

Callers that leave them unset keep upstream behavior. Unit tests in
`hpack/encoder.rs` and `frame/headers.rs` cover both.

## Go's `net/http` request header block

XDRIVE reaches an HTTP storage the way Xray-core v26.10.31 does, through Go's
`net/http` HTTP/2 client, which writes a request's pseudo-headers as
`:authority`, `:method`, `:path`, `:scheme` (`internal/httpcommon`
`encodeHeaders`). `go_request_pseudo_order(true)` writes that order; it takes
precedence over `authority_after_method`. `go_hpack_choices(true)` now also
indexes as Go's `hpack.Encoder` does: a field goes into the dynamic table
whenever it fits, where upstream never indexes `:path`, `authorization`,
`content-length` and a few other names, nor a field larger than three quarters
of the table. With both, the block is the one Go's encoder writes; with a table
of size zero, as the MASQUE client sets, nothing is indexed either way. Callers
that leave them unset keep upstream behavior; unit tests in `frame/headers.rs`
and `hpack/encoder.rs` cover them.

## Fuzzing build

`lib.rs` allows `missing_docs` on the `cfg(fuzzing)` bridge module
unconditionally; upstream allows it only with the `unstable` feature. Cargo caps
the lints of registry crates, but this copy is a path dependency, so its
`deny(missing_docs)` applies, and cargo-fuzz's `--cfg fuzzing` build failed on
the undocumented bridge. Behavior is unchanged.

## Frames read into allocations of their own size

`codec::FramedRead` reads each frame by itself: its 9-byte header into an
inline array, then the frame into a `Vec` sized from the length the header
gives, handed to the decoder whole. A frame up to 16,384 B of payload (the
protocol's default maximum) is one allocation of exactly its size; a larger one
starts at 16,393 B and doubles, ending at exactly its size. Between frames the
reader holds no heap. A DATA frame's payload is that allocation, shared with
nothing.

Upstream read through tokio-util's `FramedRead` and `LengthDelimitedCodec`: one
`BytesMut` that reserved each frame's length, was never shrunk, and handed
frames out with `split_to`. A frame queued in a stream then kept alive the
allocation it was cut from, with the bytes of its neighbours, and an
allocation grew to the largest frame, twice its size while another frame was
held. XHTTP's client advertises Go's 1 MiB SETTINGS_MAX_FRAME_SIZE, which the
server sees and which stays; only how the client stores what it reads changes.

Behavior is otherwise upstream's: a length above SETTINGS_MAX_FRAME_SIZE is a
FRAME_SIZE_ERROR as soon as the length's three bytes are in, EOF inside a frame
is the I/O error "bytes remaining on stream", EOF between frames ends the
stream, and after a read error the next poll ends it. Unit tests in
`codec/framed_read.rs` cover each, frames cut at every size, and the
allocation sizes.

## Drained frame buffers give their slots back

`proto::streams::buffer::Buffer`, the slab that queues frames for every stream
of a connection (received DATA waiting for its reader, DATA and HEADERS waiting
to be sent), kept every slot it had grown to: one per frame queued at once, 512
for a 4 MiB window of 8 KiB frames. Once it is empty it now keeps at most 4 KiB
of slots, and gives the rest back. A unit test in `buffer.rs` covers both
sides of that bound.
