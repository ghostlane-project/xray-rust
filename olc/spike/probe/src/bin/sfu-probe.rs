//! Probe (a): str0m joins the SaluteJazz connector the way the engine's carrier does, and
//! echoes through the room.
//!
//!   sfu-probe --url ws://HOST/connector --room abc123 --password passw0rd \
//!             [--dtls dimpl|boring] [--version 12|13|auto] [--stun str0m|chrome] \
//!             [--host-ip A.B.C.D] [--msgs 60] [--datagrams 200] [--bulk 4194304] [--timeout 45]
//!
//! The signalling is the engine's (internal/engine/salutejazz at 2d4266af): the join, the
//! subscriber PC the SFU offers (answered here), the publisher PC offered from here once the
//! subscriber's `_reliable` and `_lossy` are open, trickled ICE with usernameFragment on
//! both, and LiveKit DataPackets on the publisher's channels; what the room sends arrives on
//! the subscriber's. The echo partner is whoever else is in the room (the engine's own
//! Session in the Go test, go/zz_spike_echo_test.go).
//!
//! Checks: every reliable message comes back byte for byte; datagrams come back (counted);
//! a bulk transfer comes back whole. Prints `RESULT <json>`, `MEM <phase> <json>`, and the
//! wire taps (`STUN_TX/RX`, `DTLS_CH_TX/RX`); exits 0 when every check holds.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use olc_spike_probe::peer::Peer;
use olc_spike_probe::util::{chrome_ice_creds, default_ipv4, uuid4, Args};
use olc_spike_probe::{crypto, lk, mem};
use serde_json::{json, Map, Value};
use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::config::{CryptoProvider, DtlsVersion};
use str0m::{Candidate, Event, IceConnectionState};
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

const SUB: &str = "SUBSCRIBER";
const PUB: &str = "PUBLISHER";
const WEB_ORIGIN: &str = "https://salutejazz.ru";
const WEB_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

/// The reliable messages' sizes, cycled: below and above one SCTP chunk, and near the
/// engine's record size.
const SIZES: [usize; 7] = [16, 512, 1100, 1300, 4096, 8192, 15000];
const DATAGRAM_SEQ: u32 = 1_000_000;
const BULK_SEQ: u32 = 2_000_000;
const BULK_CHUNK: usize = 16_000;
const BULK_IN_FLIGHT: usize = 1 << 20;

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("FAIL: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn payload(seq: u32, len: usize) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len).map(|i| (seq as usize).wrapping_mul(31).wrapping_add(i) as u8).collect();
    let n = len.min(4);
    v[..n].copy_from_slice(&seq.to_be_bytes()[..n]);
    v
}

fn seq_of(b: &[u8]) -> Option<u32> {
    (b.len() >= 4).then(|| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

struct Sig {
    ws: WebSocket<MaybeTlsStream<TcpStream>>,
    room: String,
    group: Option<String>,
}

impl Sig {
    fn connect(url: &str, room: &str) -> Result<Self, String> {
        let mut req = url.into_client_request().map_err(|e| format!("url: {e}"))?;
        req.headers_mut().insert("Origin", HeaderValue::from_static(WEB_ORIGIN));
        req.headers_mut().insert("User-Agent", HeaderValue::from_static(WEB_UA));
        let (mut ws, _) = tungstenite::connect(req).map_err(|e| format!("connect: {e}"))?;
        // Non-blocking from here: the loop polls the socket between str0m's turns.
        if let MaybeTlsStream::Plain(s) = ws.get_mut() {
            s.set_nonblocking(true).map_err(|e| e.to_string())?;
            s.set_nodelay(true).map_err(|e| e.to_string())?;
        }
        Ok(Sig { ws, room: room.to_string(), group: None })
    }

    /// One frame in the engine's envelope order: roomId, payload, event, groupId, requestId.
    fn send(&mut self, event: &str, payload: Value) -> Result<(), String> {
        let mut m = Map::new();
        m.insert("roomId".into(), Value::String(self.room.clone()));
        m.insert("payload".into(), payload);
        m.insert("event".into(), Value::String(event.into()));
        if event != "join" {
            if let Some(g) = &self.group {
                m.insert("groupId".into(), Value::String(g.clone()));
            }
        }
        m.insert("requestId".into(), Value::String(uuid4()));
        match self.ws.send(Message::text(Value::Object(m).to_string())) {
            Ok(()) => Ok(()),
            // Queued in tungstenite's buffer; `flush` finishes it.
            Err(tungstenite::Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(format!("ws send: {e}")),
        }
    }

    fn flush(&mut self) -> Result<(), String> {
        match self.ws.flush() {
            Ok(()) => Ok(()),
            Err(tungstenite::Error::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(format!("ws flush: {e}")),
        }
    }

    fn media(&mut self, payload: Value) -> Result<(), String> {
        self.send("media-in", payload)
    }

    fn poll(&mut self) -> Result<Option<Value>, String> {
        match self.ws.read() {
            Ok(Message::Text(t)) => serde_json::from_str(t.as_str()).map(Some).map_err(|e| format!("frame: {e}")),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) =>
            {
                Ok(None)
            }
            Err(e) => Err(format!("ws read: {e}")),
        }
    }
}

fn ice_frame(candidate: &str, ufrag: &str, target: &str) -> Value {
    json!({
        "method": "rtc:ice",
        "rtcIceCandidates": [{
            "candidate": candidate, "sdpMid": "0", "sdpMLineIndex": 0,
            "usernameFragment": ufrag, "target": target,
        }],
    })
}

#[derive(Default)]
struct Marks {
    joined: Option<u128>,
    sub_connected: Option<u128>,
    sub_open: Option<u128>,
    pub_connected: Option<u128>,
    pub_open: Option<u128>,
    echoed: Option<u128>,
    bulk_start: Option<u128>,
    bulk_done: Option<u128>,
}

struct Probe {
    start: Instant,
    sig: Sig,
    provider: Arc<CryptoProvider>,
    version: DtlsVersion,
    ip: IpAddr,
    client_role: bool,
    sub: Option<Peer>,
    publ: Option<Peer>,
    pending: Option<SdpPendingOffer>,
    answered: bool,
    early: Vec<(String, Candidate)>,
    me: String,
    others: Vec<String>,
    sub_labels: HashMap<ChannelId, String>,
    pub_chans: Option<(ChannelId, ChannelId)>,
    pub_open: HashSet<ChannelId>,
    ice_servers: Vec<String>,
    marks: Marks,
    // the echo
    msgs: usize,
    datagrams: usize,
    bulk: usize,
    outbox: VecDeque<(bool, Vec<u8>)>,
    started: bool,
    msgs_back: HashSet<u32>,
    msgs_bad: usize,
    datagrams_back: usize,
    bulk_sent: usize,
    bulk_back: usize,
    mem: Vec<(String, String)>,
}

impl Probe {
    fn ms(&self) -> u128 {
        self.start.elapsed().as_millis()
    }

    fn handle_frame(&mut self, f: Value) -> Result<(), String> {
        let event = f["event"].as_str().unwrap_or("");
        let p = &f["payload"];
        match event {
            "join-response" => {
                self.me = p["participant"]["participantId"].as_str().unwrap_or("").to_string();
                self.sig.group = p["participantGroup"]["groupId"].as_str().map(str::to_string);
                self.marks.joined = Some(self.ms());
                eprintln!("joined as {} at {} ms", self.me, self.ms());
            }
            "error" => return Err(format!("connector error: {p}")),
            "media-out" => self.handle_media(p.clone())?,
            _ => {}
        }
        Ok(())
    }

    fn note_participants(&mut self, list: &Value) {
        for part in list.as_array().into_iter().flatten() {
            let id = part["identity"].as_str().unwrap_or("").to_string();
            if id.is_empty() || id == self.me {
                continue;
            }
            if part["state"].as_str() == Some("DISCONNECTED") {
                self.others.retain(|o| *o != id);
            } else if !self.others.contains(&id) {
                self.others.push(id);
            }
        }
    }

    fn handle_media(&mut self, p: Value) -> Result<(), String> {
        match p["method"].as_str().unwrap_or("") {
            "rtc:config" => {
                for s in p["configuration"]["iceServers"].as_array().into_iter().flatten() {
                    for u in s["urls"].as_array().into_iter().flatten() {
                        self.ice_servers.push(u.as_str().unwrap_or("").to_string());
                    }
                }
            }
            "rtc:join" => self.note_participants(&p["join"]["otherParticipants"]),
            "rtc:participants:update" => self.note_participants(&p["update"]["participants"]),
            "rtc:offer" => self.answer_subscriber(p["description"]["sdp"].as_str().unwrap_or(""))?,
            "rtc:answer" => self.accept_publisher(p["description"]["sdp"].as_str().unwrap_or(""))?,
            "rtc:ice" => {
                for c in p["rtcIceCandidates"].as_array().into_iter().flatten() {
                    let target = c["target"].as_str().filter(|t| !t.is_empty()).unwrap_or(SUB).to_string();
                    let line = c["candidate"].as_str().unwrap_or("");
                    let cand = Candidate::from_sdp_string(line).map_err(|e| format!("candidate {line:?}: {e}"))?;
                    self.add_remote(target, cand);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn add_remote(&mut self, target: String, cand: Candidate) {
        let ready = if target == PUB { self.answered } else { self.sub.is_some() };
        let peer = if target == PUB { self.publ.as_mut() } else { self.sub.as_mut() };
        match peer {
            Some(p) if ready => p.rtc.add_remote_candidate(cand),
            _ => self.early.push((target, cand)),
        }
    }

    fn flush_early(&mut self, target: &str) {
        let (now, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.early).into_iter().partition(|(t, _)| t == target);
        self.early = keep;
        let peer = if target == PUB { self.publ.as_mut() } else { self.sub.as_mut() };
        if let Some(p) = peer {
            for (_, c) in now {
                p.rtc.add_remote_candidate(c);
            }
        }
    }

    fn answer_subscriber(&mut self, sdp: &str) -> Result<(), String> {
        if self.sub.is_some() {
            return Err("a second subscriber offer".into());
        }
        // str0m answers an actpass offer as the DTLS server. Chrome answers as the client
        // (a=setup:active), so the offer is read as passive and str0m takes the client role.
        let sdp = if self.client_role { sdp.replace("a=setup:actpass", "a=setup:passive") } else { sdp.to_string() };
        let offer = SdpOffer::from_sdp_string(&sdp).map_err(|e| format!("subscriber offer: {e}"))?;
        let mut p = Peer::new("sub", self.ip, &self.provider, self.version, chrome_ice_creds()).map_err(|e| e.to_string())?;
        let answer = p.rtc.sdp_api().accept_offer(offer).map_err(|e| format!("accept offer: {e}"))?;
        self.sig.media(json!({
            "method": "rtc:answer",
            "description": {"sdp": answer.to_sdp_string(), "type": "answer"},
        }))?;
        let line = p.add_host_candidate()?;
        let ufrag = p.creds.ufrag.clone();
        self.sig.media(ice_frame(&line, &ufrag, SUB))?;
        p.pump()?;
        self.sub = Some(p);
        self.flush_early(SUB);
        Ok(())
    }

    fn offer_publisher(&mut self) -> Result<(), String> {
        let mut p = Peer::new("pub", self.ip, &self.provider, self.version, chrome_ice_creds()).map_err(|e| e.to_string())?;
        let mut api = p.rtc.sdp_api();
        let rel = api.add_channel_with_config(ChannelConfig {
            label: "_reliable".into(),
            ordered: true,
            reliability: Reliability::Reliable,
            negotiated: None,
            protocol: String::new(),
        });
        let lossy = api.add_channel_with_config(ChannelConfig {
            label: "_lossy".into(),
            ordered: true,
            reliability: Reliability::MaxRetransmits { retransmits: 0 },
            negotiated: None,
            protocol: String::new(),
        });
        let (offer, pending) = api.apply().ok_or("str0m made no publisher offer")?;
        self.sig.media(json!({
            "method": "rtc:offer",
            "description": {"sdp": offer.to_sdp_string(), "type": "offer"},
        }))?;
        let line = p.add_host_candidate()?;
        let ufrag = p.creds.ufrag.clone();
        self.sig.media(ice_frame(&line, &ufrag, PUB))?;
        p.pump()?;
        self.publ = Some(p);
        self.pending = Some(pending);
        self.pub_chans = Some((rel, lossy));
        Ok(())
    }

    fn accept_publisher(&mut self, sdp: &str) -> Result<(), String> {
        let pending = self.pending.take().ok_or("a publisher answer with no offer out")?;
        let answer = SdpAnswer::from_sdp_string(sdp).map_err(|e| format!("publisher answer: {e}"))?;
        let p = self.publ.as_mut().ok_or("no publisher")?;
        p.rtc.sdp_api().accept_answer(pending, answer).map_err(|e| format!("accept answer: {e}"))?;
        self.answered = true;
        self.flush_early(PUB);
        if let Some(p) = self.publ.as_mut() {
            p.pump()?;
        }
        Ok(())
    }

    /// Drives one peer and takes its events.
    fn drive(&mut self, publisher: bool) -> Result<bool, String> {
        let peer = if publisher { self.publ.as_mut() } else { self.sub.as_mut() };
        let Some(p) = peer else { return Ok(false) };
        let any = p.receive()?;
        p.tick()?;
        let events: Vec<Event> = p.events.drain(..).collect();
        let progressed = any || !events.is_empty();
        for e in events {
            self.on_event(publisher, e)?;
        }
        Ok(progressed)
    }

    fn on_event(&mut self, publisher: bool, e: Event) -> Result<(), String> {
        let name = if publisher { "pub" } else { "sub" };
        let now = self.ms();
        match e {
            Event::IceConnectionStateChange(s) => {
                eprintln!("{name}: ice {s:?} at {now} ms");
                if s == IceConnectionState::Disconnected {
                    return Err(format!("{name}: ICE disconnected"));
                }
            }
            Event::Connected => {
                eprintln!("{name}: connected (ICE+DTLS) at {now} ms");
                if publisher {
                    self.marks.pub_connected = Some(now);
                } else {
                    self.marks.sub_connected = Some(now);
                }
            }
            Event::ChannelOpen(id, label) => {
                eprintln!("{name}: channel {label} open at {now} ms");
                if publisher {
                    self.pub_open.insert(id);
                    if self.pub_open.len() == 2 {
                        self.marks.pub_open = Some(now);
                    }
                } else {
                    self.sub_labels.insert(id, label);
                    let labels: HashSet<&str> = self.sub_labels.values().map(String::as_str).collect();
                    if labels.contains("_reliable") && labels.contains("_lossy") && self.marks.sub_open.is_none() {
                        self.marks.sub_open = Some(now);
                        self.offer_publisher()?;
                    }
                }
            }
            Event::ChannelData(d) if !publisher => self.on_data(&d.data)?,
            Event::ChannelClose(_) => return Err(format!("{name}: a channel closed")),
            _ => {}
        }
        Ok(())
    }

    fn on_data(&mut self, frame: &[u8]) -> Result<(), String> {
        let Some(pkt) = lk::decode(frame) else { return Ok(()) };
        if pkt.sender == self.me {
            return Err("the room relayed our own packet back".into());
        }
        let Some(seq) = seq_of(&pkt.payload) else { return Ok(()) };
        if seq >= BULK_SEQ {
            self.bulk_back += pkt.payload.len();
        } else if seq >= DATAGRAM_SEQ {
            if pkt.topic.as_deref() != Some(lk::DATAGRAM_TOPIC) {
                return Err(format!("datagram {seq} came back under topic {:?}", pkt.topic));
            }
            self.datagrams_back += 1;
        } else {
            let want = payload(seq, SIZES[seq as usize % SIZES.len()]);
            if pkt.payload != want {
                self.msgs_bad += 1;
            }
            self.msgs_back.insert(seq);
        }
        Ok(())
    }

    fn echo_target(&self) -> Option<String> {
        self.others.first().cloned()
    }

    /// Queues the reliable messages and the datagrams once both lanes are up.
    fn start_echo(&mut self) {
        let Some(dest) = self.echo_target() else { return };
        for seq in 0..self.msgs as u32 {
            let body = payload(seq, SIZES[seq as usize % SIZES.len()]);
            self.outbox.push_back((false, lk::encode(&body, None, &[&dest], true)));
        }
        for i in 0..self.datagrams as u32 {
            let body = payload(DATAGRAM_SEQ + i, 200);
            self.outbox.push_back((true, lk::encode(&body, Some(lk::DATAGRAM_TOPIC), &[&dest], false)));
        }
        self.started = true;
        self.mem.push(("connected".into(), mem::report("connected").json()));
        mem::reset_peak();
    }

    /// Writes what the publisher's channels will take now.
    fn flush_outbox(&mut self) -> Result<bool, String> {
        let (Some((rel, lossy)), Some(p)) = (self.pub_chans, self.publ.as_mut()) else { return Ok(false) };
        let mut wrote = false;
        while let Some((is_lossy, frame)) = self.outbox.front() {
            let id = if *is_lossy { lossy } else { rel };
            let Some(mut ch) = p.rtc.channel(id) else { break };
            if !ch.write(true, frame).map_err(|e| format!("write: {e}"))? {
                break;
            }
            self.outbox.pop_front();
            wrote = true;
        }
        if wrote {
            p.pump()?;
        }
        Ok(wrote)
    }

    fn feed_bulk(&mut self) {
        let Some(dest) = self.echo_target() else { return };
        while self.bulk_sent < self.bulk && self.bulk_sent.saturating_sub(self.bulk_back) < BULK_IN_FLIGHT && self.outbox.len() < 8 {
            let n = BULK_CHUNK.min(self.bulk - self.bulk_sent);
            let body = payload(BULK_SEQ + (self.bulk_sent / BULK_CHUNK) as u32, n.max(4));
            self.bulk_sent += body.len();
            self.outbox.push_back((false, lk::encode(&body, None, &[&dest], true)));
        }
    }

    fn done(&self) -> bool {
        self.marks.bulk_done.is_some()
    }
}

fn run() -> Result<(), String> {
    let args = Args::from_env();
    let url = args.get("url").ok_or("--url is required")?;
    let room = args.or("room", "abc123");
    let password = args.or("password", "passw0rd");
    let name = args.or("name", "str0m-probe");
    let dtls = args.or("dtls", "dimpl");
    let version_name = args.or("version", "12");
    let timeout = Duration::from_secs(args.num("timeout", 45)? as u64);
    if args.or("stun", "str0m") == "chrome" {
        is::stun::set_stun_profile(is::stun::StunProfile::Chrome);
    }
    let ip = match args.get("host-ip") {
        Some(s) => s.parse().map_err(|_| format!("--host-ip: {s}"))?,
        None => default_ipv4().ok_or("no default IPv4 address: pass --host-ip")?,
    };
    let base = mem::report("start");
    let start = Instant::now();
    let mut sig = Sig::connect(&url, &room)?;
    sig.send(
        "join",
        json!({
            "password": password, "participantName": name,
            "supportedFeatures": {"attachedRooms": true, "sessionGroups": true, "transcription": true, "interpretation": true},
            "isSilent": false,
        }),
    )?;
    let mut probe = Probe {
        start,
        sig,
        provider: crypto::provider(&dtls)?,
        version: crypto::version(&version_name)?,
        ip,
        client_role: args.or("role", "client") == "client",
        sub: None,
        publ: None,
        pending: None,
        answered: false,
        early: Vec::new(),
        me: String::new(),
        others: Vec::new(),
        sub_labels: HashMap::new(),
        pub_chans: None,
        pub_open: HashSet::new(),
        ice_servers: Vec::new(),
        marks: Marks::default(),
        msgs: args.num("msgs", 60)?,
        datagrams: args.num("datagrams", 200)?,
        bulk: args.num("bulk", 4 << 20)?,
        outbox: VecDeque::new(),
        started: false,
        msgs_back: HashSet::new(),
        msgs_bad: 0,
        datagrams_back: 0,
        bulk_sent: 0,
        bulk_back: 0,
        mem: vec![("start".into(), base.json())],
    };
    let mut datagram_grace: Option<Instant> = None;
    while !probe.done() {
        if start.elapsed() > timeout {
            return Err(format!(
                "timeout after {timeout:?}: joined {:?} sub {:?}/{:?} pub {:?}/{:?} peers {:?} msgs {}/{} datagrams {}/{} bulk {}/{}",
                probe.marks.joined,
                probe.marks.sub_connected,
                probe.marks.sub_open,
                probe.marks.pub_connected,
                probe.marks.pub_open,
                probe.others,
                probe.msgs_back.len(),
                probe.msgs,
                probe.datagrams_back,
                probe.datagrams,
                probe.bulk_back,
                probe.bulk
            ));
        }
        let mut progressed = false;
        probe.sig.flush()?;
        while let Some(f) = probe.sig.poll()? {
            probe.handle_frame(f)?;
            progressed = true;
        }
        progressed |= probe.drive(false)?;
        progressed |= probe.drive(true)?;
        if !probe.started && probe.pub_open.len() == 2 && probe.echo_target().is_some() {
            probe.start_echo();
        }
        if probe.started {
            progressed |= probe.flush_outbox()?;
            let msgs_in = probe.msgs_back.len() == probe.msgs;
            // Datagrams are lossy by design: once the reliable lane has all its echoes, they get
            // a second more and are then counted, not awaited.
            if msgs_in && probe.marks.echoed.is_none() {
                let all_datagrams = probe.datagrams_back == probe.datagrams;
                let grace = *datagram_grace.get_or_insert_with(|| Instant::now() + Duration::from_secs(1));
                if all_datagrams || Instant::now() >= grace {
                    probe.marks.echoed = Some(probe.ms());
                    probe.mem.push(("echoed".into(), mem::report("echoed").json()));
                    mem::reset_peak();
                    probe.marks.bulk_start = Some(probe.ms());
                }
            }
            if probe.marks.bulk_start.is_some() && probe.marks.bulk_done.is_none() {
                probe.feed_bulk();
                if probe.bulk_back >= probe.bulk {
                    probe.marks.bulk_done = Some(probe.ms());
                    probe.mem.push(("bulk".into(), mem::report("bulk").json()));
                }
            }
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let _ = probe.sig.ws.close(None);
    let _ = probe.sig.ws.flush();

    if let Some(p) = &probe.sub {
        p.taps.print("sub");
    }
    if let Some(p) = &probe.publ {
        p.taps.print("pub");
    }
    let handshakes: Vec<Value> =
        crypto::handshakes_json().iter().filter_map(|h| serde_json::from_str(h).ok()).collect();
    let m = &probe.marks;
    let bulk_ms = m.bulk_done.unwrap_or(0).saturating_sub(m.bulk_start.unwrap_or(0));
    let mbit = if bulk_ms > 0 { probe.bulk_back as f64 * 8.0 / 1e6 / (bulk_ms as f64 / 1e3) } else { 0.0 };
    let mems: Map<String, Value> =
        probe.mem.iter().map(|(k, v)| (k.clone(), serde_json::from_str(v).unwrap_or(Value::Null))).collect();
    let result = json!({
        "probe": "sfu", "dtls": dtls, "version": version_name, "role": if probe.client_role {"client"} else {"server"},
        "stun": format!("{:?}", is::stun::stun_profile()),
        "me": probe.me, "peers": probe.others, "ice_servers": probe.ice_servers,
        "joined_ms": m.joined, "sub_connected_ms": m.sub_connected, "sub_open_ms": m.sub_open,
        "pub_connected_ms": m.pub_connected, "pub_open_ms": m.pub_open, "echoed_ms": m.echoed,
        "msgs": probe.msgs, "msgs_back": probe.msgs_back.len(), "msgs_bad": probe.msgs_bad,
        "datagrams": probe.datagrams, "datagrams_back": probe.datagrams_back,
        "bulk_bytes": probe.bulk_back, "bulk_ms": bulk_ms, "bulk_mbit_s": (mbit * 10.0).round() / 10.0,
        "dtls_handshakes": handshakes, "mem": mems,
    });
    println!("RESULT {result}");
    if probe.msgs_bad > 0 {
        return Err(format!("{} reliable messages came back different", probe.msgs_bad));
    }
    Ok(())
}
