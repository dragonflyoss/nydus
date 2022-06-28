import requests
import logging
import json
from argparse import ArgumentParser
import time
import enum
import sys
import os

sys.path.append(os.path.realpath("framework"))
import requests_unixsocket

try:
    from utils import logging_setup
    logging_setup()
except:
    print("not setup logging")
    pass


class Fop(enum.Enum):
    Getattr = 0
    Readlink = 1
    Open = 2
    Release = 3
    Read = 4
    Statfs = 5
    Getxattr = 6
    Listxattr = 7
    Opendir = 8
    Lookup = 9
    Readdir = 10
    Readdirplus = 11
    Access = 12
    Forget = 13
    BatchForget = 14
    Max = 15

    def get_value(self):
        return self.value


API_ROOT = "api/v1"
FOP_READ_IDX = 4
ROOT_MOUNTPOINT = "/"

requests_unixsocket.monkeypatch()


def check_resp(func):
    def wrapped(*args):
        resp = func(*args)
        assert resp.status_code < 400 or resp.status_code == 501, resp.content.decode(
            "utf-8"
        )

        if resp.status_code == 501:
            logging.warning("Not supported")

        return resp

    return wrapped


def exit_on_disconnecion(func):
    def wrapped(*args):
        try:
            resp = func(*args)
        except requests.exceptions.ConnectionError:
            logging.error("Can't connect to nydusd")
            exit(1)

        return resp

    return wrapped


def convert_to_dict(func):
    def wrapped(*args):
        resp = func(*args)
        return resp.json()

    return wrapped


def raw_json_body(func):
    def wrapped(*args):
        resp = func(*args)
        return json.dumps(resp.json())

    return wrapped


def retry_request(interval, **kargs):
    def inner(func):
        def wrapped(*args):
            total = kargs["total"]
            resp = None
            while total > 0:
                try:
                    resp = func(*args)
                    if resp.status_code != 503:
                        break
                    else:
                        time.sleep(interval)
                        total -= interval
                except requests.exceptions.ConnectionError as exc:
                    # Server may not start to listen on socket
                    time.sleep(interval)
                    total -= interval
                    if total <= 0:
                        raise exc
            return resp

        return wrapped

    return inner


class NydusAPIClient:
    def __init__(self, path_to_socket):
        encoded_path = path_to_socket.replace("/", "%2F").rstrip("/")
        self.root_url = f"http+unix://{encoded_path}/{API_ROOT}/"

    def build_path(self, path):
        return self.root_url + path

    @convert_to_dict
    @check_resp
    @exit_on_disconnecion
    def get_global_metrics(self, id=None) -> dict:
        query = "" if id is None else f"?id={id}"
        path = self.build_path(f"metrics{query}")
        resp = requests.get(path)
        return resp

    @exit_on_disconnecion
    def get_files_metrics(self, id=None) -> dict:
        query = "" if id is None else f"?id={id}"
        path = self.build_path(f"metrics/files{query}")
        resp = requests.get(path)
        return resp.json()

    @exit_on_disconnecion
    def get_latest_files_metrics(self, id=None) -> dict:
        query = "" if id is None else f"?id={id}"
        path = self.build_path(f"metrics/files?latest=true")
        resp = requests.get(path)
        return resp.json()

    @exit_on_disconnecion
    def get_access_patterns(self, id=None) -> dict:
        query = "" if id is None else f"?id={id}"
        path = self.build_path(f"metrics/pattern{query}")
        resp = requests.get(path)
        return resp.json()

    @exit_on_disconnecion
    def get_backend_metrics(self, id=None):
        query = "" if id is None else f"?id={id}"
        path = self.build_path(f"metrics/backend{query}")
        resp = requests.get(path)
        return resp.json()

    @exit_on_disconnecion
    def get_inflight_metrics(self):
        path = self.build_path(f"metrics/inflight")
        resp = requests.get(path)
        if resp.status_code == 204:
            print("No inflight requests")
            return None
        else:
            print(resp.content)
            return resp.json()

    @convert_to_dict
    @exit_on_disconnecion
    @retry_request(0.2, total=2)
    def get_blobcache_metrics(self, id=None):
        query = "" if id is None else f"?id={id}"
        path = self.build_path(f"metrics/blobcache{query}")
        resp = requests.get(path)
        return resp

    @raw_json_body
    @exit_on_disconnecion
    def get_daemon_info(self):
        path = self.build_path(f"daemon")
        resp = requests.get(path)
        return resp

    @exit_on_disconnecion
    def get_events(self) -> dict:
        path = self.build_path("daemon/events")
        resp = requests.get(path)
        return resp.json()

    def get_wait_daemon(self, wait_state=None):
        total = 40
        while total:
            try:
                resp = requests.get(self.root_url + "daemon")
                r = resp.json()
                logging.info(r)

                if wait_state != None:
                    if r["state"] == wait_state:
                        break
                else:
                    break
            except Exception as exc:
                logging.error(
                    "Fail to request to nydus, will %s retry. %s",
                    "" if wait_state is not None else "not",
                    exc,
                )

                if wait_state is None:
                    break
            finally:
                time.sleep(0.1)
                total -= 1

        assert total != 0

    @check_resp
    def enable_files_metrics(self, id):
        body_json = json.dumps({"iostats_files_recording": True})
        path = self.build_path(f"metrics?id={id}")
        resp = requests.put(
            path, data=body_json, headers={"Content-Type": "application/json"}
        )
        return resp

    @check_resp
    def disable_files_metrics(self, rafs_id):
        body_json = json.dumps({"iostats_files_recording": False})
        resp = requests.put(
            self.root_url + "metrics" + "?id=" + rafs_id,
            data=body_json,
            headers={"Content-Type": "application/json"},
        )
        return resp

    @raw_json_body
    @exit_on_disconnecion
    def show_daemon_backend(self, mp=None) -> dict:
        query = "" if mp is None else f"?mountpoint={mp}"
        path = self.build_path(f"daemon/backend{query}")
        resp = requests.get(path)
        return resp

    def show_daemon_events(self):
        path = self.build_path(f"daemon/events")
        resp = requests.get(path)
        return resp

    def set_daemon_log_level(self, level):
        body_json = json.dumps({"log_level": level})
        path = self.build_path(f"daemon")
        resp = requests.put(path, data=body_json)

    @check_resp
    def pseudo_fs_mount(
        self, bootstrap, mountpoint, config, prefetch_files: list = None, fs_type="rafs"
    ):

        with open(config) as f:
            d = {
                "source": bootstrap,
                "config": f.read(),
                "fs_type": fs_type,
            }

        if prefetch_files is not None:
            d["prefetch_files"] = prefetch_files

        return requests.post(
            self.build_path(f"mount?mountpoint={mountpoint}"), data=json.dumps(d)
        )

    @check_resp
    def umount_rafs(self, mountpoint):
        return requests.delete(self.build_path(f"mount?mountpoint={mountpoint}"))

    @check_resp
    def swap_backend(self, mountpoint, new_bootstrap, new_cfg):

        with open(new_cfg) as f:
            d = {
                "source": new_bootstrap,
                "config": f.read(),
                "fs_type": "rafs",
            }
        return requests.put(
            self.build_path(f"mount?mountpoint={mountpoint}"), data=json.dumps(d)
        )

    @check_resp
    @retry_request(0.2, total=2)
    def send_fuse_fd(self, path):
        resp = requests.put(self.build_path("daemon/fuse/sendfd"))
        return resp

    @check_resp
    def takeover(self):
        resp = requests.put(self.build_path("daemon/fuse/takeover"))
        return resp

    def takeover_nocheck(self):
        resp = requests.put(self.build_path("daemon/fuse/takeover"))
        # assert resp.status_code == 400

    @check_resp
    @retry_request(0.2, total=2)
    def do_exit(self):
        resp = requests.put(self.build_path("daemon/exit"))
        return resp


def calculate_average_latency(new_report: dict, old_report: dict, interval):
    total_elapse = [
        r - l
        for (l, r) in zip(
            old_report["fop_cumulative_latency_total"],
            new_report["fop_cumulative_latency_total"],
        )
    ]

    read_hits = [
        r - l for (l, r) in zip(old_report["fop_hits"], new_report["fop_hits"])
    ]

    avg_lat = [
        (l / r / interval if r != 0 else 0) for (l, r) in zip(total_elapse, read_hits)
    ]

    return avg_lat


def output_interval_reports(lat):
    fmt = "%-20s %-15.2f"
    slogan_line = "%-20s %-15s" % ("FOP", "LATENCY/us")
    read_op_line = fmt % ("READ", lat[Fop.Read.get_value()])
    lookup_op_line = fmt % ("LOOKUP", lat[Fop.Lookup.get_value()])
    print(slogan_line)
    print(read_op_line)
    print(lookup_op_line)
    print()


def output_summary_reports(report: dict):
    fmt = "%-20s %-15u"
    slogan_line = "%-20s %-15s" % ("FOP", "No. of Calls")
    fops_stats = []
    fops_stats.append(fmt % ("READ", report["fop_hits"][Fop.Read.get_value()]))
    fops_stats.append(fmt % ("GETATTR", report["fop_hits"][Fop.Getattr.get_value()]))
    fops_stats.append(fmt % ("READLINK", report["fop_hits"][Fop.Readlink.get_value()]))
    fops_stats.append(fmt % ("OPEN", report["fop_hits"][Fop.Open.get_value()]))
    fops_stats.append(fmt % ("RELEASE", report["fop_hits"][Fop.Release.get_value()]))
    fops_stats.append(fmt % ("STATFS", report["fop_hits"][Fop.Statfs.get_value()]))
    fops_stats.append(fmt % ("GETXATTR", report["fop_hits"][Fop.Getxattr.get_value()]))
    fops_stats.append(
        fmt % ("LISTXATTR", report["fop_hits"][Fop.Listxattr.get_value()])
    )
    fops_stats.append(fmt % ("OPENDIR", report["fop_hits"][Fop.Opendir.get_value()]))
    fops_stats.append(fmt % ("LOOKUP", report["fop_hits"][Fop.Lookup.get_value()]))
    fops_stats.append(fmt % ("READDIR", report["fop_hits"][Fop.Readdir.get_value()]))
    fops_stats.append(
        fmt % ("READDIRPLUS", report["fop_hits"][Fop.Readdirplus.get_value()])
    )
    fops_stats.append(fmt % ("ACCESS", report["fop_hits"][Fop.Access.get_value()]))
    fops_stats.append(fmt % ("FORGET", report["fop_hits"][Fop.Forget.get_value()]))
    fops_stats.append(
        fmt % ("BATCHFORGET", report["fop_hits"][Fop.BatchForget.get_value()])
    )
    print(slogan_line)
    print("\n".join(fops_stats))
    print("\nCumulative Data Read: %s bytes" % report["data_read"])


class BackendMetrics:
    @staticmethod
    def calculate_metrics(last_report, report, interval):
        bps = (
            report["read_amount_total"] - last_report["read_amount_total"]
        ) / interval
        ops = (report["read_count"] - last_report["read_count"]) / interval

        print("BW(KB/S):    %u" % (bps // 1024))
        print("OPS:         %u" % (ops))


def daemon_set_args(subparsers):
    daemon_parser = subparsers.add_parser("daemon")
    daemon_parser.add_argument(
        "--backend", dest="backend", action="store_true", required=False
    )
    daemon_parser.add_argument(
        "--events", dest="events", action="store_true", required=False
    )
    daemon_parser.add_argument(
        "--mountpoint", type=str, dest="mountpoint", required=False
    )
    daemon_parser.add_argument(
        "--log-level", type=str, dest="log_level", required=False
    )


def stats_set_args(subparsers):
    stats_parser = subparsers.add_parser("stats")
    stats_parser.add_argument(
        "-I",
        "--interval",
        help="Time in seconds between two reports",
        type=int,
        default=0,
    )
    stats_parser.add_argument("-S", "--summary", help="Summary", action="store_true")
    stats_parser.add_argument(
        "--id", help="", type=str, dest="id", default=ROOT_MOUNTPOINT
    )


def blobcache_set_args(subparsers):
    blobcache_parser = subparsers.add_parser("blobcache")
    blobcache_parser.add_argument(
        "--id", help="", type=str, dest="id", default=ROOT_MOUNTPOINT
    )


def backend_set_args(subparsers):
    backend_parser = subparsers.add_parser("backend")
    backend_parser.add_argument("-I", "--interval", type=int, default=0, required=False)
    backend_parser.add_argument(
        "--id", help="", type=str, dest="id", default=ROOT_MOUNTPOINT
    )


def events_set_args(subparsers):
    subparsers.add_parser("events")


def execute_dameon(nc: NydusAPIClient, args):

    resp = nc.get_daemon_info()
    print(resp)

    if args.backend:
        r = nc.show_daemon_backend(args.mountpoint)
        print(r)

    if args.events:
        r = nc.show_daemon_events()
        print(r)

    if hasattr(args, "log_level"):
        nc.set_daemon_log_level(args.log_level)


def execute_stats(nc, args):
    interval = args.interval
    summary = args.summary
    fs_id = args.id

    last_report = nc.get_global_metrics(fs_id)

    if summary:
        output_summary_reports(last_report)

    while interval:
        time.sleep(interval)
        report = nc.get_global_metrics(fs_id)
        al = calculate_average_latency(report, last_report, interval)
        output_interval_reports(al)
        last_report = report


def execute_blobcache(nc, args):
    backend_id = args.id
    resp = nc.get_blobcache_metrics(backend_id)
    print(resp)


def execute_backend(nc, args):
    backend_id = args.id
    resp = nc.get_backend_metrics(backend_id)
    print(resp)

    interval = args.interval
    last_report = nc.get_backend_metrics(backend_id)

    while interval:
        time.sleep(interval)
        report = nc.get_backend_metrics(backend_id)
        BackendMetrics.calculate_metrics(last_report, report, interval)
        last_report = report


def execute_events(nc, args):
    resp = nc.get_events()
    print(json.dumps(resp))


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--sock", help="Specify unix socket path")
    subparsers = parser.add_subparsers(dest="mode")

    daemon_set_args(subparsers)
    stats_set_args(subparsers)
    blobcache_set_args(subparsers)
    backend_set_args(subparsers)
    events_set_args(subparsers)

    args = parser.parse_args()
    sock = args.sock

    if sock is None or not len(sock):
        logging.error("No unix socket was specified!")
        exit(1)

    try:
        nc = NydusAPIClient(sock)
    except requests.exceptions.ConnectionError:
        logging.error("Can't connect to nydusd")
        exit(1)

    if args.mode == "stats":
        execute_stats(nc, args)
    elif args.mode == "daemon":
        execute_dameon(nc, args)
    elif args.mode == "blobcache":
        execute_blobcache(nc, args)
    elif args.mode == "backend":
        execute_backend(nc, args)
    elif args.mode == "events":
        execute_events(nc, args)
