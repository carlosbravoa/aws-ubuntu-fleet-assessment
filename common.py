"""Shared helpers for the entry point and the transports (no transport-specific code)."""
import base64
import gzip
import json
from pathlib import Path

from botocore.config import Config
from rich.console import Console

COLLECTOR = Path(__file__).with_name("collector.py")
BOTO_CFG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

console = Console(stderr=True)


def log(msg):
    console.log(msg)


def list_regions(session):
    ec2 = session.client("ec2", region_name=session.region_name or "us-east-1", config=BOTO_CFG)
    return sorted(r["RegionName"] for r in ec2.describe_regions()["Regions"])


def pick_regions(session, opts, extra=""):
    """Regions to scan, from --all-regions / --region / the AWS config."""
    if opts.all_regions:
        return list_regions(session)
    if opts.regions:
        return opts.regions
    if session.region_name:
        return [session.region_name]
    raise SystemExit(f"No region configured: use --region or --all-regions{extra}")


def decode_blob(line):
    """Decode the collector's single "PFA1:<base64 gzip json>" output line."""
    try:
        return json.loads(gzip.decompress(base64.b64decode(line[5:])))
    except Exception as e:  # noqa: BLE001
        return {"error": f"cannot decode collector output: {e}"}


def region_result(region, instances=(), skipped=(), unmanaged=(), error=None):
    """The one shape every transport returns per region."""
    r = {"region": region, "instances": list(instances), "skipped": list(skipped),
         "unmanaged": list(unmanaged)}
    if error:
        r["error"] = error
    return r
