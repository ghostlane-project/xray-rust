#!/usr/bin/env bash
# deploy.sh up <dir>            start the lab's Jitsi Meet deployment
# deploy.sh bosh-only <dir>     close its XMPP WebSocket: only BOSH is left
# deploy.sh first <dir>         what Jicofo made of the Rust client's answer
#                               about itself (first.sh on the logs so far)
# deploy.sh bosh <dir> rust|all whose XMPP went over BOSH, by the front's and
#                               Prosody's logs so far (bosh.sh)
# deploy.sh collect <dir> <out> the containers' logs and settings into <out>
# deploy.sh down <dir>          stop it
#
# A Jitsi Meet deployment of the lab's own, for one job of a GitHub-hosted
# runner (.github/workflows/olc-jitsi-live.yml): a pinned stable release of
# docker-jitsi-meet (Prosody, Jicofo, the videobridge, the web front), each
# image as the release's own compose file names it. Nothing here touches a
# public Jitsi host: the bridge is told its address (no STUN lookup), and the
# clients reach the front by a name /etc/hosts gives this machine.
#
# It starts containers, binds 443 and 10000/udp and edits /etc/hosts, so it
# runs on a GitHub-hosted runner only (GITHUB_ACTIONS=true and a runner's
# temporary directory): never on the build box, never on a host of ours.
#
#   - the front: https://meet.jitsi-live.test (443), its certificate a leaf
#     of a CA made for the run; the front serves the leaf and the CA. The
#     Go server and client trust the CA by SSL_CERT_FILE (the system's roots
#     and it); the Rust client by OLC_TLS_TEST_PIN, the CA's SHA-256;
#   - the bridge: UDP 10000, advertising this machine's own address (the
#     default route's), which the clients on this machine and the bridge's
#     container both reach; its container address is advertised too;
#   - Prosody logs every stanza (mod_stanza_debug at debug level): what a
#     real Jicofo and Prosody say is the run's evidence, and a difference
#     from the Go fake becomes a test vector. The lab's own rooms alone.
#
# up writes <dir>/lab.env (NAME=value lines) for run.sh:
# OLCRTC_GATE_JITSI_LIVE_HOST, SSL_CERT_FILE, OLC_TLS_TEST_PIN.
set -euo pipefail

DJM_REPO=https://github.com/jitsi/docker-jitsi-meet
# stable-11248-3, published 2026-11-02.
DJM_TAG=stable-11248-3
DJM_COMMIT=fca3e3a578a1bdd527c20b9d86a31cfc362d5426
LAB_HOST=meet.jitsi-live.test
PROJECT=olc-jitsi-live
SERVICES=(web prosody jicofo jvb)

die() {
	echo "jitsi-live: $*" >&2
	exit 1
}

usage="usage: deploy.sh up <dir> | bosh-only <dir> | first <dir> | bosh <dir> rust|all | collect <dir> <out> | down <dir>"
what=${1:?$usage}
dir=${2:?$usage}

if [ "${GITHUB_ACTIONS:-}" != true ] || [ -z "${RUNNER_TEMP:-}" ]; then
	die "this starts containers and edits /etc/hosts: a GitHub-hosted runner's job only"
fi

compose() {
	docker compose --project-directory "$dir/djm" -p "$PROJECT" "$@"
}

# setting <NAME> <value>: the one line NAME=value of the deployment's .env.
setting() {
	sed -i "/^$1=/d" "$dir/djm/.env"
	printf '%s=%s\n' "$1" "$2" >>"$dir/djm/.env"
}

# front <path> [curl flags...]: a request to the front with the lab's CA.
front() {
	local path=$1
	shift
	curl -sS --max-time 10 --cacert "$dir/tls/ca.crt" "$@" "https://$LAB_HOST$path"
}

# upgrade_code: the status the front answers an XMPP WebSocket upgrade with.
# The handshake's nonce is 16 random bytes made here, as RFC 6455 has it.
upgrade_code() {
	local nonce
	nonce=$(head -c 16 /dev/urandom | base64)
	front '/xmpp-websocket?room=probe' --http1.1 -o /dev/null -w '%{http_code}' --max-time 3 \
		-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
		-H "Sec-WebSocket-Key: $nonce" -H 'Sec-WebSocket-Protocol: xmpp' 2>/dev/null || true
}

up() {
	local ip pin
	mkdir -p "$dir/tls" "$dir/config"
	[ ! -e "$dir/djm" ] || die "$dir/djm exists: one deployment a directory"

	# The release, by its commit.
	git init -q "$dir/djm"
	git -C "$dir/djm" fetch -q --depth 1 "$DJM_REPO" "$DJM_COMMIT"
	git -C "$dir/djm" -c advice.detachedHead=false checkout -q FETCH_HEAD
	[ "$(git -C "$dir/djm" rev-parse HEAD)" = "$DJM_COMMIT" ] || die "docker-jitsi-meet is not at $DJM_COMMIT"
	grep -q "$DJM_TAG" "$dir/djm/docker-compose.yml" || die "the compose file does not name $DJM_TAG"

	ip=$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
	[[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no address on the default route"

	# The lab's CA and the front's certificate (a leaf, the CA after it).
	cat >"$dir/tls/ca.cnf" <<-'EOF'
		[req]
		distinguished_name = dn
		x509_extensions = v3_ca
		prompt = no
		[dn]
		CN = olc jitsi-live lab CA
		[v3_ca]
		basicConstraints = critical,CA:TRUE
		keyUsage = critical,keyCertSign,cRLSign
		subjectKeyIdentifier = hash
	EOF
	cat >"$dir/tls/leaf.cnf" <<-EOF
		basicConstraints = critical,CA:FALSE
		keyUsage = critical,digitalSignature
		extendedKeyUsage = serverAuth
		subjectAltName = DNS:$LAB_HOST
		authorityKeyIdentifier = keyid
	EOF
	openssl req -x509 -new -config "$dir/tls/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-days 3 -keyout "$dir/tls/ca.key" -out "$dir/tls/ca.crt" 2>/dev/null
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$LAB_HOST" \
		-keyout "$dir/tls/leaf.key" -out "$dir/tls/leaf.csr" 2>/dev/null
	openssl x509 -req -in "$dir/tls/leaf.csr" -CA "$dir/tls/ca.crt" -CAkey "$dir/tls/ca.key" -CAcreateserial \
		-days 3 -extfile "$dir/tls/leaf.cnf" -out "$dir/tls/leaf.crt" 2>/dev/null
	openssl verify -CAfile "$dir/tls/ca.crt" "$dir/tls/leaf.crt" >/dev/null || die "the leaf does not verify under the lab's CA"
	pin=$(openssl x509 -in "$dir/tls/ca.crt" -outform der | sha256sum | cut -d' ' -f1)
	[ ${#pin} -eq 64 ] || die "no pin for the lab's CA"
	cat /etc/ssl/certs/ca-certificates.crt "$dir/tls/ca.crt" >"$dir/tls/roots.pem"

	# The deployment's settings.
	cp "$dir/djm/env.example" "$dir/djm/.env"
	(cd "$dir/djm" && bash ./gen-passwords.sh)
	setting CONFIG "$dir/config"
	setting HTTP_PORT 8000
	setting HTTPS_PORT 443
	setting TZ UTC
	setting PUBLIC_URL "https://$LAB_HOST"
	setting RESTART_POLICY no
	setting ENABLE_LETSENCRYPT 0
	setting JVB_ADVERTISE_IPS "$ip"
	setting JVB_DISABLE_STUN 1
	setting GLOBAL_MODULES stanza_debug
	setting LOG_LEVEL debug

	# Every host directory a container mounts, made before Docker makes it
	# root's: the containers run as an unprivileged user. (The pattern is the
	# compose file's own ${CONFIG}, to the letter.)
	# shellcheck disable=SC2016
	grep -o '\${CONFIG}/[^:]*' "$dir/djm/docker-compose.yml" | sort -u | while read -r path; do
		mkdir -p "$dir/config/${path#\$\{CONFIG\}/}"
	done
	mkdir -p "$dir/config/web/keys"
	cat "$dir/tls/leaf.crt" "$dir/tls/ca.crt" >"$dir/config/web/keys/cert.crt"
	cp "$dir/tls/leaf.key" "$dir/config/web/keys/cert.key"
	chmod -R a+rwX "$dir/config"

	grep -q "[[:space:]]$LAB_HOST\$" /etc/hosts || echo "$ip $LAB_HOST" | sudo tee -a /etc/hosts >/dev/null

	compose pull -q
	compose up -d
	compose images

	# The front answers with a config.js that names the XMPP domain.
	local n ok=
	for n in $(seq 1 60); do
		if front /config.js 2>/dev/null | grep -q 'config.hosts.domain'; then
			ok=1
			break
		fi
		sleep 2
	done
	[ -n "$ok" ] || {
		compose ps -a
		compose logs --no-color --tail 40 web
		die "the front did not serve config.js within 120 s"
	}
	echo "jitsi-live: the front serves config.js (after $((n * 2)) s)"
	front /config.js | grep -E '^config\.(hosts\.|bosh|websocket)|^var subd' || true

	# Jicofo has a bridge to put a conference on: until then a room gets no
	# offer. The bridge says so itself; 120 s, then the run goes on and says.
	ok=
	for n in $(seq 1 60); do
		if compose logs --no-color jicofo 2>/dev/null | grep -q -i 'added new videobridge'; then
			ok=1
			break
		fi
		sleep 2
	done
	if [ -n "$ok" ]; then
		echo "jitsi-live: Jicofo has a bridge (after $((n * 2)) s)"
	else
		echo "jitsi-live: WARNING: Jicofo's log names no bridge after 120 s"
		compose logs --no-color --tail 20 jicofo jvb || true
	fi

	# What the front says to an XMPP WebSocket upgrade and to a BOSH request,
	# for the log.
	echo "jitsi-live: the WebSocket upgrade: $(upgrade_code)"
	echo "jitsi-live: BOSH: $(front '/http-bind?room=probe' -o /dev/null -w '%{http_code}' 2>/dev/null || true)"

	{
		echo "OLCRTC_GATE_JITSI_LIVE_HOST=$LAB_HOST"
		echo "SSL_CERT_FILE=$dir/tls/roots.pem"
		echo "OLC_TLS_TEST_PIN=$pin"
	} >"$dir/lab.env"
	echo "jitsi-live: up: https://$LAB_HOST at $ip, docker-jitsi-meet $DJM_TAG ($DJM_COMMIT)"
}

# started <service>...: each service's container and the moment it started,
# one a line: the same text before and after means none was made again or
# restarted.
started() {
	local s id
	for s in "$@"; do
		id=$(compose ps -q "$s")
		[ -n "$id" ] || die "no container of $s"
		printf '%s %s\n' "$s" "$(docker inspect -f '{{.Id}} {{.State.StartedAt}}' "$id")"
	done
}

# bosh_only: the release's own switch (ENABLE_XMPP_WEBSOCKET=0) on the front:
# its nginx has no /xmpp-websocket location any more (the path is answered
# as a room's page, with no upgrade) and config.js names no websocket, so a
# client's WebSocket dial fails and BOSH (/http-bind) is all that is left.
#
# The front alone is made again (--no-deps). Prosody's environment names the
# same setting, so without it the release's compose file makes Prosody again
# too: Jicofo then drops its bridge, the bridge does not come back to the
# brewery room within a minute, and no room gets an offer, the Go client's
# included (run 44929668208: "There are no operational bridges"). The check
# after the switch holds that: the three other containers are the ones that
# were running before it.
bosh_only() {
	local n before
	before=$(started prosody jicofo jvb)
	setting ENABLE_XMPP_WEBSOCKET 0
	compose up -d --no-deps --force-recreate web
	[ "$(started prosody jicofo jvb)" = "$before" ] || {
		compose ps -a
		die "the switch restarted more than the front: a room would get no offer"
	}
	for n in $(seq 1 30); do
		if front /config.js 2>/dev/null | grep -q 'config.hosts.domain'; then
			break
		fi
		sleep 2
	done
	if front /config.js | grep -q '^config.websocket'; then
		die "config.js still names a WebSocket"
	fi
	front /config.js | grep -E '^config\.(hosts\.|bosh|websocket)' || true
	echo "jitsi-live: the WebSocket upgrade now: $(upgrade_code)"
}

# first: Jicofo's and Prosody's logs so far, read by first.sh (which says
# what it holds): the run before it had the Rust client join a room of its
# own ahead of everyone (run.sh with -olcrtc.gate-jitsi-live-first).
first() {
	local tmp
	tmp=$(mktemp -d)
	compose logs --no-color jicofo >"$tmp/jicofo.log" 2>&1
	compose logs --no-color prosody >"$tmp/prosody.log" 2>&1
	bash "$(dirname "$0")/first.sh" "$tmp/jicofo.log" "$tmp/prosody.log"
}

# bosh: the front's and Prosody's logs so far, read by bosh.sh (which says
# what it holds): the run before it had the Rust client's XMPP go over BOSH
# (run.sh with -olcrtc.gate-jitsi-live-bosh). The front's log is its
# container's: bosh-only makes the front again, so after it the log holds
# only what came since.
bosh() {
	local tmp
	tmp=$(mktemp -d)
	compose logs --no-color web >"$tmp/web.log" 2>&1
	compose logs --no-color prosody >"$tmp/prosody.log" 2>&1
	bash "$(dirname "$0")/bosh.sh" "$tmp/web.log" "$tmp/prosody.log" "$1"
}

# collect: the four containers' logs, what the front serves and the settings
# the release wrote, with the run's generated passwords taken out.
collect() {
	local out=$1 s f value
	mkdir -p "$out"
	compose ps -a >"$out/ps.txt" 2>&1 || true
	compose images >"$out/images.txt" 2>&1 || true
	for s in "${SERVICES[@]}"; do
		compose logs --no-color --timestamps "$s" >"$out/$s.log" 2>&1 || true
	done
	front /config.js >"$out/config.js" 2>&1 || true
	for f in jicofo/jicofo.conf jvb/jvb.conf prosody/config/prosody.cfg.lua prosody/config/conf.d/jitsi-meet.cfg.lua; do
		if [ -f "$dir/config/$f" ]; then
			cp "$dir/config/$f" "$out/$(basename "$f")" 2>/dev/null || true
		fi
	done
	grep -v -i 'PASSWORD\|SECRET\|TOKEN' "$dir/djm/.env" | grep -v '^#' | grep -v '^$' >"$out/settings.env" || true
	# The generated passwords, and a SASL PLAIN answer that carries one.
	while IFS='=' read -r _ value; do
		[ ${#value} -ge 16 ] || continue
		grep -r -l -F -- "$value" "$out" 2>/dev/null | while read -r f; do
			sed -i "s/$value/<password>/g" "$f"
		done
	done < <(grep -i 'PASSWORD=' "$dir/djm/.env" || true)
	find "$out" -type f -name '*.log' -exec sed -i -E 's#(<auth [^>]*>)[^<]*(</auth>)#\1<scrubbed>\2#g' {} +
	wc -c "$out"/* | tail -n 12
}

case "$what" in
up) up ;;
bosh-only) bosh_only ;;
first) first ;;
bosh) bosh "${3:?$usage}" ;;
collect) collect "${3:?$usage}" ;;
down) compose down -v --remove-orphans ;;
*) die "$usage" ;;
esac
