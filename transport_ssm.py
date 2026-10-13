"""SSM transport: discover online Ubuntu managed nodes and run the collector via Run Command."""
import base64
import gzip
import time
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from common import BOTO_CFG, COLLECTOR, decode_blob, log, pick_regions, region_result

NAME = "SSM"
DEFAULT_WORKERS = 8  # regions in parallel
SEND_BATCH = 50  # send_command accepts up to 50 instance ids
TERMINAL = {"Success", "Failed", "Cancelled", "TimedOut", "Undeliverable", "Terminated",
            "InvalidPlatform", "AccessDenied"}


def add_arguments(ap):
    g = ap.add_argument_group("SSM transport")
    g.add_argument("--max-concurrency", default="50", metavar="N|N%",
                   help="instances SSM runs the collector on at once, per batch (default 50)")
    g.add_argument("--max-errors", default="100%", metavar="N|N%",
                   help="SSM MaxErrors: failures before a batch is aborted (default 100%%, never abort)")
    return {"max_concurrency": "50", "max_errors": "100%"}  # defaults, for cross-transport checks


def session(opts):
    return boto3.Session(profile_name=opts.profile)


# ----------------------------------------------------------------------------- discovery

def _nodes(ssm, region, instance_ids, tags):
    """Return (targets, skipped) for a region. Targets are online Ubuntu SSM nodes."""
    # SSM refuses to mix tag filters with other filters: filter tags server side, the rest here
    filters = [{"Key": f"tag:{k}", "Values": [v]} for k, v in tags]
    targets, skipped = [], []
    for page in ssm.get_paginator("describe_instance_information").paginate(Filters=filters):
        for n in page["InstanceInformationList"]:
            if instance_ids and n["InstanceId"] not in instance_ids:
                continue
            node = {"region": region, "instance_id": n["InstanceId"], "name": n.get("ComputerName", ""),
                    "platform": f'{n.get("PlatformName", "")} {n.get("PlatformVersion", "")}'.strip(),
                    "ping": n.get("PingStatus")}
            if n.get("PingStatus") != "Online":
                skipped.append({**node, "reason": f"SSM agent {n.get('PingStatus')}"})
            elif "ubuntu" not in n.get("PlatformName", "").lower():
                skipped.append({**node, "reason": "not Ubuntu"})
            else:
                targets.append(node)
    return targets, skipped


def _ec2_inventory(sess, region):
    """Name tags for EC2 instances plus running EC2 instances not managed by SSM (coverage gap)."""
    ec2 = sess.client("ec2", region_name=region, config=BOTO_CFG)
    names, running = {}, set()
    for page in ec2.get_paginator("describe_instances").paginate():
        for r in page["Reservations"]:
            for i in r["Instances"]:
                tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
                names[i["InstanceId"]] = tags.get("Name", "")
                if i["State"]["Name"] == "running":
                    running.add(i["InstanceId"])
    return names, running


def _discover_region(sess, region, opts):
    try:
        targets, skipped = _nodes(sess.client("ssm", region_name=region, config=BOTO_CFG),
                                  region, opts.instance_ids, opts.tags)
        names, running = _ec2_inventory(sess, region)
    except (ClientError, BotoCoreError) as e:
        log(f"[red]{region}[/]: {e}")
        return region_result(region, error=str(e))
    managed = {t["instance_id"] for t in targets} | {s["instance_id"] for s in skipped}
    unmanaged = [] if (opts.instance_ids or opts.tags) else sorted(running - managed)
    for n in targets + skipped:
        n["name"] = names.get(n["instance_id"]) or n["name"]
    if not targets and (skipped or unmanaged):
        log(f"[cyan]{region}[/]: no online Ubuntu SSM nodes ({len(skipped)} skipped, {len(unmanaged)} unmanaged)")
    return region_result(region, targets, skipped,
                         [{"instance_id": i, "name": names.get(i, "")} for i in unmanaged])


def discover(sess, opts):
    regions = pick_regions(sess, opts)
    log(f"Scanning {len(regions)} region(s) over SSM: {', '.join(regions)}")
    with ThreadPoolExecutor(max_workers=opts.workers) as pool:
        return list(pool.map(lambda r: _discover_region(sess, r, opts), regions))


# ----------------------------------------------------------------------------- execution

def _fetch_result(ssm, cmd_id, iid, status):
    try:
        out = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
    except ClientError as e:
        return {"error": f"{status}: {e}"}
    stdout = out.get("StandardOutputContent", "")
    for line in stdout.splitlines():
        if line.startswith("PFA1:"):
            return decode_blob(line)
    err = (out.get("StandardErrorContent") or stdout or status).strip()
    return {"error": f"{status}: {err[-400:]}"}


def _run_collector(sess, region, targets, opts):
    ssm = sess.client("ssm", region_name=region, config=BOTO_CFG)
    timeout = opts.timeout
    b64 = base64.b64encode(gzip.compress(COLLECTOR.read_bytes())).decode()
    args = " --skip-apt-update" if opts.skip_apt_update else ""
    commands = [f"echo '{b64}' | base64 -d | gunzip > /tmp/.pro_fleet_assess.py",
                f"python3 /tmp/.pro_fleet_assess.py{args}; rc=$?; rm -f /tmp/.pro_fleet_assess.py; exit $rc"]
    results = {}
    ids = [t["instance_id"] for t in targets]
    cmd_ids = []
    for i in range(0, len(ids), SEND_BATCH):
        batch = ids[i:i + SEND_BATCH]
        resp = ssm.send_command(InstanceIds=batch, DocumentName="AWS-RunShellScript",
                                Comment="pro-fleet-assess (read-only)", TimeoutSeconds=timeout,
                                MaxConcurrency=opts.max_concurrency, MaxErrors=opts.max_errors,
                                Parameters={"commands": commands, "executionTimeout": [str(timeout)]})
        cmd_ids.append((resp["Command"]["CommandId"], batch))
    log(f"[cyan]{region}[/]: sent collector to {len(ids)} instance(s)")

    deadline = time.time() + timeout + 120
    pending = {(c, iid) for c, batch in cmd_ids for iid in batch}
    while pending and time.time() < deadline:
        time.sleep(5)
        for cmd_id, _ in cmd_ids:
            for page in ssm.get_paginator("list_command_invocations").paginate(CommandId=cmd_id):
                for inv in page["CommandInvocations"]:
                    key = (cmd_id, inv["InstanceId"])
                    if key in pending and inv["Status"] in TERMINAL:
                        pending.discard(key)
                        results[inv["InstanceId"]] = _fetch_result(ssm, cmd_id, inv["InstanceId"], inv["Status"])
    for _, iid in pending:
        results[iid] = {"error": "timed out waiting for SSM command"}
    return results


def _run_region(sess, reg, opts):
    if not reg["instances"]:
        return reg
    res = _run_collector(sess, reg["region"], reg["instances"], opts)
    for t in reg["instances"]:
        t["data"] = res.get(t["instance_id"], {"error": "no result"})
    return reg


def run(sess, regional, opts):
    with ThreadPoolExecutor(max_workers=opts.workers) as pool:
        return list(pool.map(lambda reg: _run_region(sess, reg, opts), regional))
