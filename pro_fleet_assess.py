#!/usr/bin/env python3
"""Ubuntu Pro fleet assessment, over AWS SSM (default) or SSH.

Runs a read-only collector (collector.py) on every Ubuntu machine it finds and reports
Pro attachment, pending updates per pocket (security / updates / ESM-Infra / ESM-Apps /
...), reboot status, kernel, OS release and installed-package sources.

  --transport ssm   online Ubuntu SSM managed nodes in one or more regions (no SSH keys)
  --transport ssh   EC2 instances reached over SSH, or an explicit --host list (no SSM agent)

Examples:
  ./pro_fleet_assess.py                                   # default region from AWS config
  ./pro_fleet_assess.py -r us-east-1 -r eu-west-1 --details
  ./pro_fleet_assess.py --all-regions --limit 50 --json report.json --csv report.csv
  ./pro_fleet_assess.py -r us-east-1 --tag Env=prod --skip-apt-update
  ./pro_fleet_assess.py --transport ssh -k ~/.ssh/key.pem -r us-east-1
  ./pro_fleet_assess.py --transport ssh -k key.pem -H 10.0.0.5 -H admin@db1:2222 --private-ip -J bastion
"""
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

import transport_ssh
import transport_ssm
from common import log

TRANSPORTS = {"ssm": transport_ssm, "ssh": transport_ssh}
POCKETS = ["security", "updates", "esm-infra", "esm-apps", "backports", "proposed", "other"]

def apply_limit(regional, limit):
    """Cap the number of instances assessed, in region order; the rest are reported as skipped."""
    if not limit:
        return
    budget = limit
    for reg in regional:
        keep, drop = reg["instances"][:budget], reg["instances"][budget:]
        budget -= len(keep)
        reg["instances"] = keep
        for n in drop:
            reg["skipped"].append({**n, "reason": f"not scanned (--limit {limit} reached)"})
    dropped = sum(1 for reg in regional for x in reg["skipped"] if x["reason"].startswith("not scanned"))
    if dropped:
        log(f"[yellow]--limit {limit}[/]: assessing {limit} instance(s), {dropped} left unscanned")


# ----------------------------------------------------------------------------- reporting

def row_fields(inst):
    """Flatten one instance result into the fields used by table and CSV."""
    d = inst["data"]
    pro = d.get("pro", {})
    summ = pro.get("summary", {})
    pc = d.get("pocket_counts", {})
    br = pro.get("security_breakdown", {})
    enabled = sorted(k for k, v in (pro.get("services") or {}).items() if v == "enabled")
    rr = summ.get("reboot_required")
    reboot = rr if rr else ("yes" if d.get("reboot_required") else "no")
    src = d.get("package_sources") or {}
    third = sum(v for k, v in src.items() if k.startswith("3rd-party:")) if "error" not in src else None
    return {
        "region": inst["region"], "instance_id": inst["instance_id"], "name": inst.get("name", ""),
        "hostname": d.get("hostname", ""), "os": d.get("os", {}).get("description", ""),
        "release": d.get("os", {}).get("release", ""), "codename": d.get("os", {}).get("codename", ""),
        "kernel": d.get("kernel", ""), "pro_client": pro.get("version"),
        "pro_attached": pro.get("attached"), "pro_account": pro.get("account"), "pro_contract": pro.get("contract"),
        "pro_expires": pro.get("expires"), "pro_enabled_services": " ".join(enabled),
        "installed_packages": summ.get("num_installed_packages", d.get("installed_packages")),
        "pkgs_main": summ.get("num_main_packages"), "pkgs_restricted": summ.get("num_restricted_packages"),
        "pkgs_universe": summ.get("num_universe_packages"), "pkgs_multiverse": summ.get("num_multiverse_packages"),
        "pkgs_esm_infra": summ.get("num_esm_infra_packages"), "pkgs_esm_apps": summ.get("num_esm_apps_packages"),
        "pkgs_third_party": summ.get("num_third_party_packages", third),
        "pkgs_unknown": summ.get("num_unknown_packages"),
        "third_party_sources": " ".join(f"{k[10:]}={v}" for k, v in sorted(src.items()) if k.startswith("3rd-party:")),
        **{f"upd_{p.replace('-', '_')}": pc.get(p, 0) for p in POCKETS},
        **{f"{p.replace('-', '_')}_available_with_pro": d["needs_pro_counts"].get(p, 0) if "needs_pro_counts" in d
           else sum(v for k, v in br.get(p, {}).items() if k.startswith("pending")) for p in ("esm-infra", "esm-apps")},
        "reboot_required": reboot, "reboot_pkgs": " ".join(d.get("reboot_required_pkgs", [])),
        "livepatch_fixed_cves": pro.get("livepatch_fixed_cves"),
        "warnings": "; ".join(d.get("warnings", []) + [v for k, v in pro.items() if k.endswith("_error")]),
    }


def fmt_count(n, style):
    return f"[{style}]{n}[/]" if n else "[dim]0[/]"


def esm_cell(total, pending):
    if not total:
        return "[dim]0[/]"
    if pending:
        return f"[yellow]{total}[/] [dim]({'needs Pro' if pending == total else f'{pending} need Pro'})[/]"
    return f"[green]{total}[/]"


MAX_LIST = 15  # per-instance notice lines printed before collapsing (fleets can be large)


def head(items):
    return items[:MAX_LIST]


def more(out, items, what):
    if len(items) > MAX_LIST:
        out.print(f"[dim]... and {len(items) - MAX_LIST} more {what} (full list in --json / --csv)[/]")


def render(report, details, transport="SSM"):
    out = Console()
    t = Table(title=f"Ubuntu Pro fleet assessment — {report['generated_at']}", show_lines=False, header_style="bold")
    for col, kw in [("Region", {}), ("Instance", {}), ("Name", {"max_width": 22}), ("OS", {}), ("Kernel", {}),
                    ("Pro", {}), ("Pkgs", {"justify": "right"}), ("Sources m/r/u/mv/3p/unk", {}),
                    ("Security", {"justify": "right"}), ("Updates", {"justify": "right"}),
                    ("ESM-Infra", {"justify": "right"}), ("ESM-Apps", {"justify": "right"}),
                    ("Other", {"justify": "right"}), ("Reboot", {})]:
        t.add_column(col, **kw)
    errors, rows = [], []
    for reg in report["regions"]:
        for inst in reg["instances"]:
            if "error" in inst["data"]:
                errors.append(inst)
                continue
            f = row_fields(inst)
            rows.append(f)
            if f["pro_attached"]:
                pro = "[green]attached[/]" + (f"\n[dim]{f['pro_enabled_services']}[/]" if f["pro_enabled_services"] else "")
            elif f["pro_attached"] is False:
                pro = "[red]not attached[/]"
            else:
                pro = "[yellow]unknown[/]"
            src = "/".join(str(f[k] if f[k] is not None else "?") for k in
                           ("pkgs_main", "pkgs_restricted", "pkgs_universe", "pkgs_multiverse", "pkgs_third_party", "pkgs_unknown"))
            reboot = f["reboot_required"]
            reboot = f"[red]{reboot}[/]" if reboot.startswith("yes") else "[green]no[/]"
            other = f["upd_backports"] + f["upd_proposed"] + f["upd_other"]
            t.add_row(f["region"], f["instance_id"], f["name"], f"{f['release']} {f['codename']}", f["kernel"], pro,
                      str(f["installed_packages"] or "?"), src,
                      fmt_count(f["upd_security"], "red"), fmt_count(f["upd_updates"], "yellow"),
                      esm_cell(f["upd_esm_infra"], f["esm_infra_available_with_pro"]),
                      esm_cell(f["upd_esm_apps"], f["esm_apps_available_with_pro"]),
                      fmt_count(other, "cyan"), reboot)
    out.print(t)
    out.print("[dim]Sources: main/restricted/universe/multiverse/third-party/unknown. "
              "Security = standard -security pocket; Updates = non-security -updates pocket; "
              "ESM 'needs Pro' = security fixes available with an Ubuntu Pro subscription.[/]")

    if details:
        for reg in report["regions"]:
            for inst in reg["instances"]:
                d = inst["data"]
                if "error" in d:
                    continue
                pt = Table(title=f"{inst['instance_id']} ({inst.get('name') or d.get('hostname')}) — pending updates",
                           header_style="bold")
                for c in ("Package", "Installed", "Candidate", "Pocket", "Pro status"):
                    pt.add_column(c)
                ups = sorted(d.get("updates", []), key=lambda u: (POCKETS.index(u["p"]) if u["p"] in POCKETS else 99, u["n"]))
                for u in ups:
                    pt.add_row(u["n"], u.get("cur") or "", u.get("new") or "", u["p"], u.get("st", ""))
                if d.get("updates_truncated"):
                    pt.caption = "package list truncated (too large for SSM output); counts are complete"
                src = d.get("package_sources") or {}
                if src and "error" not in src:
                    pt.caption = (pt.caption + " | " if pt.caption else "") + "installed by origin: " + \
                        ", ".join(f"{k}={v}" for k, v in sorted(src.items(), key=lambda kv: -kv[1]))
                if ups or pt.caption:
                    out.print(pt)

    # Summary
    s = Table(title="Summary", show_header=False)
    s.add_column(style="bold")
    s.add_column()
    n = len(rows)
    s.add_row("Assessed instances", str(n))
    s.add_row("Pro attached", f"{sum(1 for r in rows if r['pro_attached'])}/{n}")
    s.add_row("Reboot required", str(sum(1 for r in rows if r["reboot_required"].startswith("yes"))))
    for p in POCKETS:
        k = f"upd_{p.replace('-', '_')}"
        tot = sum(r[k] for r in rows)
        if tot or p in ("security", "updates", "esm-infra", "esm-apps"):
            s.add_row(f"Pending updates: {p}", f"{tot} on {sum(1 for r in rows if r[k])} instance(s)")
    pro_fixes = [r["esm_infra_available_with_pro"] + r["esm_apps_available_with_pro"] for r in rows]
    s.add_row("Security fixes available with Ubuntu Pro", str(sum(pro_fixes)))
    s.add_row("Instances that would benefit from Ubuntu Pro", f"{sum(1 for x in pro_fixes if x)}/{n}")
    rels = {}
    for r in rows:
        rels[f"{r['release']} {r['codename']}"] = rels.get(f"{r['release']} {r['codename']}", 0) + 1
    s.add_row("Releases", ", ".join(f"{k}: {v}" for k, v in sorted(rels.items())))
    skipped = [x for reg in report["regions"] for x in reg["skipped"]]
    unmanaged = [x | {"region": reg["region"]} for reg in report["regions"] for x in reg["unmanaged"]]
    s.add_row(f"Skipped {transport} nodes", str(len(skipped)))
    if transport == "SSM":
        s.add_row("Running EC2 not in SSM", str(len(unmanaged)))
    s.add_row("Failed assessments", str(len(errors)))
    out.print(s)

    for inst in errors:
        out.print(f"[red]FAILED[/] {inst['region']} {inst['instance_id']} ({inst.get('name')}): {inst['data']['error']}")
    for x in head(skipped):
        out.print(f"[yellow]SKIPPED[/] {x['region']} {x['instance_id']} ({x.get('name')}, {x['platform']}): {x['reason']}")
    more(out, skipped, "skipped")
    for x in head(unmanaged):
        out.print(f"[yellow]NOT IN SSM[/] {x['region']} {x['instance_id']} ({x.get('name')})")
    more(out, unmanaged, "not in SSM")
    for reg in report["regions"]:
        if reg.get("error"):
            out.print(f"[red]REGION ERROR[/] {reg['region']}: {reg['error']}")
    for r in rows:
        if r["warnings"]:
            out.print(f"[yellow]WARN[/] {r['instance_id']}: {r['warnings']}")
    return rows


def write_csv(path, report):
    rows = [row_fields(i) for reg in report["regions"] for i in reg["instances"] if "error" not in i["data"]]
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


# ----------------------------------------------------------------------------- main

def parse_args():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--transport", choices=sorted(TRANSPORTS), default="ssm",
                    help="how to reach the machines (default: ssm)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("-r", "--region", action="append", dest="regions", help="region to scan (repeatable)")
    g.add_argument("-a", "--all-regions", action="store_true", help="scan every enabled region")
    ap.add_argument("--profile", help="AWS profile")
    ap.add_argument("-i", "--instance-id", action="append", dest="instance_ids",
                    help="limit to instance id (repeatable)")
    ap.add_argument("-t", "--tag", action="append", default=[],
                    help="limit to instances with tag Key=Value (repeatable)")
    ap.add_argument("--skip-apt-update", action="store_true",
                    help="do not refresh apt indexes on the instances (faster, may under-report updates)")
    ap.add_argument("-l", "--limit", type=int, metavar="N",
                    help="assess at most N instances in total (in region order); the rest are listed as skipped")
    ap.add_argument("--timeout", type=int, default=900, help="per-instance timeout in seconds (default 900)")
    ap.add_argument("--workers", type=int, metavar="N",
                    help="parallel workers: regions for SSM (default 8), hosts for SSH (default 20)")
    ap.add_argument("-d", "--details", action="store_true", help="print per-instance pending package tables")
    ap.add_argument("--json", metavar="FILE", help="write full raw report as JSON")
    ap.add_argument("--csv", metavar="FILE", help="write one-row-per-instance CSV")
    # every transport registers its own flags and reports their defaults, so that flags
    # belonging to the other transport can be rejected instead of silently ignored
    defaults = {name: mod.add_arguments(ap) for name, mod in TRANSPORTS.items()}

    o = ap.parse_args()
    o.tags = [tuple(t.split("=", 1)) for t in o.tag]
    if any(len(t) != 2 for t in o.tags):
        ap.error("--tag must be Key=Value")
    for name, defs in defaults.items():
        if name == o.transport:
            continue
        used = [k for k, v in defs.items() if getattr(o, k, v) != v]
        if used:
            ap.error(f"--{used[0].replace('_', '-')} belongs to --transport {name}, "
                     f"but --transport {o.transport} was selected")
    validate = getattr(TRANSPORTS[o.transport], "validate", None)
    if validate:
        validate(ap, o)
    if o.workers is None:
        o.workers = TRANSPORTS[o.transport].DEFAULT_WORKERS
    return o


def main():
    opts = parse_args()
    transport = TRANSPORTS[opts.transport]
    session = transport.session(opts)

    regional = transport.discover(session, opts)
    apply_limit(regional, opts.limit)
    regional = transport.run(session, regional, opts)

    report = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
              "transport": opts.transport,
              "regions": [r for r in regional if r["instances"] or r["skipped"] or r["unmanaged"] or r.get("error")]}

    render(report, opts.details, transport=transport.NAME)
    if opts.json:
        Path(opts.json).write_text(json.dumps(report, indent=2, default=str))
        log(f"JSON report written to {opts.json}")
    if opts.csv:
        write_csv(opts.csv, report)
        log(f"CSV report written to {opts.csv}")


if __name__ == "__main__":
    main()
