"""SSH transport: stream the collector to each host and run it with `sudo python3 -`.

Targets come either from EC2 (running instances in one or more regions) or from an
explicit host list (-H / --hosts-file), which needs no AWS access at all.
"""
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from common import BOTO_CFG, COLLECTOR, decode_blob, log, pick_regions, region_result

NAME = "SSH"
DEFAULT_WORKERS = 20  # hosts in parallel


def add_arguments(ap):
    g = ap.add_argument_group("SSH transport")
    g.add_argument("-k", "--identity", help="SSH private key (.pem) used for every host (required)")
    g.add_argument("-u", "--user", default="ubuntu", help="SSH user (default: ubuntu)")
    g.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    g.add_argument("-J", "--jump", help="bastion / ProxyJump host, e.g. ubuntu@bastion:22")
    g.add_argument("-o", "--ssh-option", action="append", default=[], help="extra ssh -o option (repeatable)")
    g.add_argument("--no-host-key-check", action="store_true",
                   help="don't verify or record host keys (ephemeral cloud IPs); default is accept-new")
    g.add_argument("--connect-timeout", type=int, default=15, help="SSH connect timeout in seconds (default 15)")
    g.add_argument("-H", "--host", action="append", default=[],
                   help="[user@]host[:port] to assess instead of discovering EC2 (repeatable)")
    g.add_argument("--hosts-file", help="file with one [user@]host[:port] per line (# comments allowed)")
    g.add_argument("--key-name", help="EC2 discovery: only instances launched with this key pair name")
    g.add_argument("--private-ip", action="store_true",
                   help="EC2 discovery: connect to private IPs (e.g. through -J bastion)")
    return {"identity": None, "user": "ubuntu", "port": 22, "jump": None, "ssh_option": [],
            "no_host_key_check": False, "connect_timeout": 15, "host": [], "hosts_file": None,
            "key_name": None, "private_ip": False}


def validate(ap, opts):
    if not opts.identity:
        ap.error("--transport ssh needs an SSH key: -k/--identity")
    if not Path(opts.identity).expanduser().is_file():
        ap.error(f"identity file not found: {opts.identity}")
    opts.identity = str(Path(opts.identity).expanduser())
    if opts.hosts_file:
        opts.host += [l.strip() for l in Path(opts.hosts_file).read_text().splitlines()
                      if l.strip() and not l.lstrip().startswith("#")]


def session(opts):
    return None if opts.host else boto3.Session(profile_name=opts.profile)


# ----------------------------------------------------------------------------- targets

def parse_host(spec, default_user, default_port):
    """[user@]host[:port] ; IPv6 as [addr] or [addr]:port."""
    user, _, hostport = spec.rpartition("@")
    user = user or default_user
    port = default_port
    if hostport.startswith("["):
        host, _, rest = hostport[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif hostport.count(":") == 1:
        host, p = hostport.split(":")
        port = int(p)
    else:
        host = hostport
    return {"region": "-", "instance_id": host, "name": spec, "host": host, "user": user, "port": port}


def _ec2_targets(sess, region, opts):
    """Running EC2 instances in a region -> (targets, skipped)."""
    ec2 = sess.client("ec2", region_name=region, config=BOTO_CFG)
    filters = [{"Name": "instance-state-name", "Values": ["running"]}]
    filters += [{"Name": f"tag:{k}", "Values": [v]} for k, v in opts.tags]
    if opts.key_name:
        filters.append({"Name": "key-name", "Values": [opts.key_name]})
    kw = {"Filters": filters}
    if opts.instance_ids:
        kw["InstanceIds"] = opts.instance_ids
    targets, skipped = [], []
    for page in ec2.get_paginator("describe_instances").paginate(**kw):
        for r in page["Reservations"]:
            for i in r["Instances"]:
                tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
                node = {"region": region, "instance_id": i["InstanceId"], "name": tags.get("Name", ""),
                        "platform": i.get("PlatformDetails", ""), "user": opts.user, "port": opts.port}
                host = i.get("PrivateIpAddress") if opts.private_ip else (i.get("PublicIpAddress") or i.get("PublicDnsName"))
                if i.get("Platform") == "windows":
                    skipped.append({**node, "reason": "Windows"})
                elif not host:
                    skipped.append({**node, "reason": "no private IP" if opts.private_ip else
                                    "no public IP (try --private-ip with -J bastion)"})
                else:
                    targets.append({**node, "host": host})
    return targets, skipped


def _discover_region(sess, region, opts):
    try:
        targets, skipped = _ec2_targets(sess, region, opts)
    except (ClientError, BotoCoreError) as e:
        log(f"[red]{region}[/]: {e}")
        return region_result(region, error=str(e))
    return region_result(region, targets, skipped)


def discover(sess, opts):
    if opts.host:
        targets = [parse_host(h, opts.user, opts.port) for h in opts.host]
        log(f"Assessing {len(targets)} host(s) from the command line over SSH")
        return [region_result("-", targets)]
    regions = pick_regions(sess, opts, extra=", or pass hosts with --host")
    log(f"Discovering EC2 instances in {len(regions)} region(s): {', '.join(regions)}")
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(lambda r: _discover_region(sess, r, opts), regions))


# ----------------------------------------------------------------------------- execution

def ssh_base(opts, t):
    cmd = ["ssh", "-i", opts.identity, "-p", str(t["port"]), "-o", "BatchMode=yes",
           "-o", f"ConnectTimeout={opts.connect_timeout}", "-o", "ServerAliveInterval=30", "-o", "LogLevel=ERROR"]
    if opts.no_host_key_check:
        cmd += ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    else:
        cmd += ["-o", "StrictHostKeyChecking=accept-new"]
    if opts.jump:
        cmd += ["-J", opts.jump]
    for o in opts.ssh_option:
        cmd += ["-o", o]
    host = f"[{t['host']}]" if ":" in t["host"] else t["host"]
    return cmd + [f"{t['user']}@{host}"]


def assess_host(t, opts, collector):
    args = " --no-output-limit" + (" --skip-apt-update" if opts.skip_apt_update else "")
    cmd = ssh_base(opts, t) + [f"sudo -n python3 -{args}"]
    try:
        p = subprocess.run(cmd, input=collector, capture_output=True, timeout=opts.timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"timed out after {opts.timeout}s"}
    out, err = p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace").strip()
    for line in out.splitlines():
        if line.startswith("PFA1:"):
            return decode_blob(line)
    if p.returncode == 255:
        return {"error": f"SSH failed: {err.splitlines()[-1] if err else 'connection error'}"}
    if "sudo" in err and "password" in err:
        return {"error": f"user {t['user']} needs passwordless sudo"}
    return {"error": f"rc={p.returncode}: {(err or out)[-400:]}"}


def run(sess, regional, opts):
    targets = [t for reg in regional for t in reg["instances"]]
    if not targets:
        return regional
    log(f"Assessing {len(targets)} host(s) over SSH (port {opts.port}, user {opts.user}"
        f"{', via ' + opts.jump if opts.jump else ''})")
    collector = COLLECTOR.read_bytes()
    with ThreadPoolExecutor(max_workers=opts.workers) as pool:
        for t, data in zip(targets, pool.map(lambda t: assess_host(t, opts, collector), targets)):
            t["data"] = data
            if t["region"] == "-" and data.get("hostname"):  # explicit hosts: show the real hostname
                t["name"] = data["hostname"].split(".")[0]
    # SSH reaches any host, so non-Ubuntu machines are only recognisable from the collector's output
    for reg in regional:
        keep = []
        for t in reg["instances"]:
            os_ = t["data"].get("os", {})
            if "error" not in t["data"] and os_.get("distributor", "").lower() != "ubuntu":
                reg["skipped"].append({**t, "platform": os_.get("description", "?"), "reason": "not Ubuntu"})
            else:
                keep.append(t)
        reg["instances"] = keep
    return regional
