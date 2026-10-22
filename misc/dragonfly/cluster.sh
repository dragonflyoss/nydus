#!/usr/bin/env bash
# Runs the single-node Dragonfly cluster (manager, scheduler, seed-peer
# dfdaemon) the e2e suite in tests/e2e/dragonfly reads through, and injects
# outages into it.
#
# Usage: cluster.sh <command> [args]
#   up [seconds]          start MySQL/Redis (docker) and every component in
#                         dependency order, then wait-ready
#   start [component...]  start the components that are not running (all by
#                         default), in dependency order
#   stop <component...>   SIGKILL components, as a crash or outage would
#   wait-ready [seconds]  wait until every component serves requests (120s)
#   status                print the state of every component
#   logs                  print the tail of every log
#   down                  stop everything, MySQL and Redis included
#
# Components: manager, scheduler, dfdaemon, probe-origin (the HTTP origin
# the readiness probe downloads through the dfdaemon proxy).
#
# Environment:
#   DF_BIN_DIR     directory holding manager, scheduler and dfdaemon
#                  (default /usr/local/bin)
#   DF_PROBE_PORT  port of the probe origin (default 18089)
#
# Run it as root: manager and scheduler keep state under
# /usr/local/dragonfly, and the e2e tests (root) stop and restart the
# components. Logs, pid files and dfdaemon storage live under /tmp/dragonfly,
# where the configs next to this script put them.
set -euo pipefail

CONFIG_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BIN_DIR=${DF_BIN_DIR:-/usr/local/bin}
RUN_DIR=/tmp/dragonfly
LOG_DIR=$RUN_DIR/logs
PID_DIR=$RUN_DIR/run
PROBE_DIR=$RUN_DIR/probe
PROBE_PORT=${DF_PROBE_PORT:-18089}

# Must match manager.yaml, scheduler.yaml and dfdaemon.yaml.
MANAGER_GRPC=127.0.0.1:65003
MANAGER_REST=127.0.0.1:8080
SCHEDULER_GRPC=127.0.0.1:8002
DFDAEMON_GRPC=127.0.0.1:4000
DFDAEMON_PROXY=127.0.0.1:4001

COMPONENTS=(manager scheduler dfdaemon probe-origin)
MYSQL=df-e2e-mysql
REDIS=df-e2e-redis

log() { echo "cluster.sh: $*" >&2; }
die() {
	log "$*"
	exit 1
}

pid_of() { cat "$PID_DIR/$1.pid" 2>/dev/null || true; }

# running reports whether the component's recorded process is alive (and not
# a zombie).
running() {
	local pid state
	pid=$(pid_of "$1")
	[[ -n $pid && -r /proc/$pid/stat ]] || return 1
	state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || return 1
	[[ -n $state && $state != Z ]]
}

launch() {
	local name=$1
	shift
	mkdir -p "$LOG_DIR" "$PID_DIR"
	# No inherited stdio: a caller capturing our output (the tests do) must
	# not wait for the daemon to exit.
	nohup "$@" </dev/null >>"$LOG_DIR/$name.stdout.log" 2>&1 &
	echo "$!" >"$PID_DIR/$name.pid"
	log "started $name (pid $!)"
}

# grpc_serving runs the standard gRPC health check (grpc.health.v1, empty
# service name) against a plaintext HTTP/2 endpoint using curl only, and
# succeeds when the server answers SERVING: the frame 00 00000002 08 01.
grpc_serving() {
	local out
	out=$(printf '\0\0\0\0\0' | curl -sS --max-time 3 --http2-prior-knowledge --noproxy '*' \
		-H 'content-type: application/grpc' -H 'te: trailers' --data-binary @- \
		"http://$1/grpc.health.v1.Health/Check" 2>/dev/null | od -An -tx1 | tr -d ' \n') || return 1
	[[ $out == 00000000020801 ]]
}

manager_ready() {
	curl -sf --max-time 3 --noproxy '*' "http://$MANAGER_REST/healthy" >/dev/null 2>&1 ||
		grpc_serving "$MANAGER_GRPC"
}

scheduler_ready() { grpc_serving "$SCHEDULER_GRPC"; }

# seed_peer_announced asks the scheduler for its seed peers the way the nydus
# Dragonfly SDK does when it builds its client (scheduler.v2 ListHosts with
# type 1, the super seed: frame 00 00000002 08 01), and succeeds when the
# reply lists at least one host. A restarted scheduler answers health checks
# before dfdaemon re-announces itself, and an SDK client built in that window
# caches an empty seed peer list.
seed_peer_announced() {
	local out
	out=$(printf '\000\000\000\000\002\010\001' | curl -sS --max-time 3 --http2-prior-knowledge --noproxy '*' \
		-H 'content-type: application/grpc' -H 'te: trailers' --data-binary @- \
		"http://$SCHEDULER_GRPC/scheduler.v2.Scheduler/ListHosts" 2>/dev/null | od -An -tx1 | tr -d ' \n') || return 1
	# Uncompressed message, non-zero length, first field is hosts (1, bytes).
	[[ ${out:0:2} == 00 && ${out:2:8} != 00000000 && ${out:10:2} == 0a ]]
}

probe_origin_ready() {
	curl -sf --max-time 3 --noproxy '*' -o /dev/null "http://127.0.0.1:$PROBE_PORT/"
}

# proxy_serves downloads a fresh random file through the dfdaemon proxy with
# P2P forced, the way the nydus Dragonfly SDK does, and checks the bytes. A new
# file each time makes dfdaemon run a new task rather than answer from its
# storage.
proxy_serves() {
	local name want got ok=1
	name=probe-$(date +%s%N)-$RANDOM
	want=$PROBE_DIR/$name
	got=$RUN_DIR/$name.got
	mkdir -p "$PROBE_DIR"
	head -c 65536 /dev/urandom >"$want"
	if curl -sf --max-time 20 --noproxy '' -x "http://$DFDAEMON_PROXY" \
		-H 'X-Dragonfly-Use-P2P: true' -o "$got" "http://127.0.0.1:$PROBE_PORT/$name" &&
		cmp -s "$want" "$got"; then
		ok=0
	fi
	rm -f "$want" "$got"
	return "$ok"
}

mysql_ready() { docker exec "$MYSQL" mysqladmin ping -h 127.0.0.1 -uroot -pdragonfly --silent >/dev/null 2>&1; }
redis_ready() { docker exec "$REDIS" redis-cli ping 2>/dev/null | grep -q PONG; }

# wait_for <seconds> <check> <name> [component]: poll check every second,
# failing early when the component it waits for has exited.
wait_for() {
	local timeout=$1 check=$2 name=$3 component=${4:-}
	local deadline=$((SECONDS + timeout))
	until "$check"; do
		if [[ -n $component ]] && ! running "$component"; then
			show_logs "$component"
			die "$name exited while starting"
		fi
		if ((SECONDS >= deadline)); then
			if [[ -n $component ]]; then
				show_logs "$component"
			fi
			die "$name not ready after ${timeout}s"
		fi
		sleep 1
	done
}

start_component() {
	local name=$1
	if running "$name"; then
		return 0
	fi
	case $name in
	manager)
		launch manager "$BIN_DIR/manager" --config "$CONFIG_DIR/manager.yaml"
		wait_for 120 manager_ready manager manager
		;;
	scheduler)
		launch scheduler "$BIN_DIR/scheduler" --config "$CONFIG_DIR/scheduler.yaml"
		wait_for 60 scheduler_ready scheduler scheduler
		;;
	dfdaemon)
		# A killed dfdaemon leaves its download socket behind.
		rm -f "$RUN_DIR/dfdaemon.sock"
		launch dfdaemon "$BIN_DIR/dfdaemon" --config "$CONFIG_DIR/dfdaemon.yaml" --log-dir "$LOG_DIR/dfdaemon"
		;;
	probe-origin)
		mkdir -p "$PROBE_DIR"
		launch probe-origin python3 -m http.server "$PROBE_PORT" --bind 127.0.0.1 --directory "$PROBE_DIR"
		wait_for 10 probe_origin_ready probe-origin probe-origin
		;;
	esac
}

stop_component() {
	local name=$1 pid
	pid=$(pid_of "$name")
	if running "$name"; then
		kill -KILL "$pid" 2>/dev/null || true
		for _ in $(seq 100); do
			running "$name" || break
			sleep 0.1
		done
		! running "$name" || die "$name (pid $pid) survived SIGKILL"
		log "killed $name (pid $pid)"
	fi
	rm -f "$PID_DIR/$name.pid"
}

# validate fails on a name that is not a component.
validate() {
	local want
	for want in "$@"; do
		[[ " ${COMPONENTS[*]} " == *" $want "* ]] || die "unknown component $want (want: ${COMPONENTS[*]})"
	done
}

# components prints the named components in dependency order; no names means
# all of them.
components() {
	local c n
	for c in "${COMPONENTS[@]}"; do
		if (($# == 0)); then
			echo "$c"
			continue
		fi
		for n in "$@"; do
			if [[ $n == "$c" ]]; then
				echo "$c"
			fi
		done
	done
}

start() {
	validate "$@"
	local c
	for c in $(components "$@"); do
		start_component "$c"
	done
}

stop() {
	(($# > 0)) || die "stop: name the components to stop"
	validate "$@"
	local c
	for c in $(components "$@"); do
		stop_component "$c"
	done
}

# wait_ready succeeds once every component actually serves: manager health,
# the scheduler's and the seed peer's gRPC health (the endpoints the nydus SDK
# dials when it builds its client), the seed peer registered with the
# scheduler, and a byte-exact P2P download through the dfdaemon proxy.
wait_ready() {
	local timeout=${1:-120} failed c
	local deadline=$((SECONDS + timeout))
	while :; do
		failed=
		for c in "${COMPONENTS[@]}"; do
			running "$c" || failed+=" $c(not running)"
		done
		if [[ -z $failed ]]; then
			manager_ready || failed+=" manager(health)"
			scheduler_ready || failed+=" scheduler(grpc health)"
			grpc_serving "$DFDAEMON_GRPC" || failed+=" dfdaemon(grpc health)"
		fi
		if [[ -z $failed ]]; then
			seed_peer_announced || failed+=" scheduler(no seed peer)"
		fi
		if [[ -z $failed ]]; then
			proxy_serves || failed+=" dfdaemon(proxy download)"
		fi
		if [[ -z $failed ]]; then
			log "ready"
			return 0
		fi
		if ((SECONDS >= deadline)); then
			log "not ready after ${timeout}s:$failed"
			show_logs
			return 1
		fi
		sleep 1
	done
}

deps() {
	docker inspect "$MYSQL" >/dev/null 2>&1 ||
		docker run -d --name "$MYSQL" -e MYSQL_ROOT_PASSWORD=dragonfly -e MYSQL_DATABASE=manager \
			-p 127.0.0.1:3306:3306 mysql:8 >/dev/null
	docker inspect "$REDIS" >/dev/null 2>&1 ||
		docker run -d --name "$REDIS" -p 127.0.0.1:6379:6379 redis:7 >/dev/null
	wait_for 180 mysql_ready mysql
	wait_for 60 redis_ready redis
}

show_logs() {
	local f
	[[ -d $LOG_DIR ]] || return 0
	while IFS= read -r f; do
		if (($# > 0)) && [[ $f != "$LOG_DIR/$1"* ]]; then
			continue
		fi
		echo "==> $f <==" >&2
		tail -n 40 "$f" >&2 || true
	done < <(find "$LOG_DIR" -type f | sort)
}

status() {
	local c
	for c in "${COMPONENTS[@]}"; do
		if running "$c"; then
			echo "$c: running (pid $(pid_of "$c"))"
		else
			echo "$c: stopped"
		fi
	done
}

down() {
	local c
	for c in dfdaemon scheduler manager probe-origin; do
		stop_component "$c"
	done
	docker rm -f "$MYSQL" "$REDIS" >/dev/null 2>&1 || true
}

cmd=${1:-}
shift || true
case $cmd in
up)
	deps
	start
	wait_ready "${1:-120}"
	;;
start) start "$@" ;;
stop) stop "$@" ;;
wait-ready) wait_ready "${1:-120}" ;;
status) status ;;
logs) show_logs ;;
down) down ;;
*)
	sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
	;;
esac
