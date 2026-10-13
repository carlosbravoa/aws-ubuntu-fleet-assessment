#!/usr/bin/env python3
"""Remote collector executed on each Ubuntu instance through SSM (AWS-RunShellScript) or SSH.

Gathers OS/kernel info, Ubuntu Pro status, `pro security-status`, pending updates
per pocket, installed package sources and reboot status, then prints a single
line: "PFA1:" + base64(gzip(json)). Must stay compatible with old Python 3
(xenial/bionic): no f-strings, no walrus, no subprocess.run(capture_output=...).
"""
import base64
import gzip
import json
import os
import re
import subprocess
import sys

MAX_OUTPUT = 23000  # SSM get_command_invocation truncates stdout at 24000 chars


def run(cmd, timeout=300):
    """Run a command, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, universal_newlines=True,
                             env=dict(os.environ, LC_ALL="C", DEBIAN_FRONTEND="noninteractive"))
        out, err = p.communicate(timeout=timeout)
        return p.returncode, out, err
    except Exception as e:  # missing binary, timeout...
        return 127, "", str(e)


def which(name):
    for d in os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(":") + ["/usr/bin", "/usr/sbin"]:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def os_info():
    info = {}
    rc, out, _ = run(["lsb_release", "-a"])
    if rc == 0:
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip().lower().replace(" ", "_")] = v.strip()
    else:  # minimal images may lack lsb_release
        try:
            with open("/etc/os-release") as f:
                kv = dict(l.strip().split("=", 1) for l in f if "=" in l)
            kv = {k: v.strip('"') for k, v in kv.items()}
            info = {"distributor_id": kv.get("NAME", ""), "description": kv.get("PRETTY_NAME", ""),
                    "release": kv.get("VERSION_ID", ""), "codename": kv.get("VERSION_CODENAME", "")}
        except Exception:
            pass
    return {
        "distributor": info.get("distributor_id", ""),
        "description": info.get("description", ""),
        "release": info.get("release", ""),
        "codename": info.get("codename", ""),
    }


def classify_suites(suites):
    """Map apt suites of a candidate version (e.g. ['focal-updates','focal-security']) to one pocket."""
    order = [
        ("esm-infra", ("-infra-security", "-infra-updates")),
        ("esm-apps", ("-apps-security", "-apps-updates")),
        ("security", ("-security",)),
        ("updates", ("-updates",)),
        ("backports", ("-backports",)),
        ("proposed", ("-proposed",)),
    ]
    for pocket, suffixes in order:
        if any(s.endswith(suf) for s in suites for suf in suffixes):
            return pocket
    return "other"


def apt_upgradable():
    """Parse `apt list --upgradable`: name/suite1,suite2 newver arch [upgradable from: oldver]."""
    rc, out, err = run(["apt", "list", "--upgradable"])
    pkgs = []
    if rc != 0:
        return pkgs, (err or "apt list failed").strip()[:300]
    rx = re.compile(r"^(\S+?)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]")
    for line in out.splitlines():
        m = rx.match(line)
        if m:
            name, suites, new, arch, cur = m.groups()
            pkgs.append({"n": name, "cur": cur, "new": new,
                         "p": classify_suites(suites.split(","))})
    return pkgs, None


def package_sources():
    """Count installed packages by origin using python3-apt (third-party sites broken out)."""
    try:
        import apt  # python3-apt, shipped on Ubuntu server images (pro depends on it)
    except Exception:
        return None
    counts = {}
    try:
        cache = apt.Cache()
        for pkg in cache:
            if not pkg.is_installed:
                continue
            key = "unknown (local/removed from archive)"
            # an outdated installed version only has the dpkg "now" origin: use the candidate's
            origins = [o for o in pkg.installed.origins if o.site] or \
                [o for o in (pkg.candidate.origins if pkg.candidate else []) if o.site]
            for o in origins:
                if not o.site:  # "now" pseudo-origin from dpkg status
                    continue
                if o.origin in ("Ubuntu", "UbuntuESM", "UbuntuESMApps", "UbuntuFIPS", "UbuntuFIPSUpdates",
                                "UbuntuCC", "UbuntuCIS", "UbuntuROS", "UbuntuRealtimeKernel"):
                    key = "Ubuntu:" + (o.component or "?") if o.origin == "Ubuntu" else o.origin
                else:
                    key = "3rd-party:" + o.site
                break
            counts[key] = counts.get(key, 0) + 1
    except Exception as e:
        return {"error": str(e)[:200]}
    return counts


def pro_data(pro):
    res = {"installed": bool(pro)}
    if not pro:
        return res
    rc, out, _ = run([pro, "version"], 30)
    res["version"] = out.strip() if rc == 0 else None

    rc, out, err = run([pro, "status", "--format", "json"], 120)
    if rc == 0:
        try:
            st = json.loads(out)
            res["attached"] = st.get("attached")
            res["account"] = (st.get("account") or {}).get("name")
            res["contract"] = (st.get("contract") or {}).get("name")
            res["expires"] = st.get("expires")
            res["services"] = {s.get("name"): s.get("status") for s in st.get("services", [])
                               if s.get("entitled") == "yes" or s.get("status") == "enabled"}
        except Exception as e:
            res["status_error"] = str(e)[:200]
    else:
        res["status_error"] = (err or out).strip()[:300]

    rc, out, err = run([pro, "security-status", "--format", "json"], 300)
    if rc != 0:
        res["security_status_error"] = (err or out).strip()[:300]
        return res
    try:
        ss = json.loads(out)
    except Exception as e:
        res["security_status_error"] = "bad json: " + str(e)[:200]
        return res
    summ = ss.get("summary", {})
    res["summary"] = {k: v for k, v in summ.items() if k != "ua"}
    if "attached" not in res:
        res["attached"] = (summ.get("ua") or {}).get("attached")
    # security updates per service, per status (upgrade_available / pending_attach / pending_enable ...)
    breakdown = {}
    for p in ss.get("packages", []):
        svc, st = p.get("service_name", "?"), p.get("status", "?")
        breakdown.setdefault(svc, {})
        breakdown[svc][st] = breakdown[svc].get(st, 0) + 1
    res["security_breakdown"] = breakdown
    res["security_packages"] = [
        {"n": p.get("package"), "new": p.get("version"), "svc": p.get("service_name"), "st": p.get("status")}
        for p in ss.get("packages", [])
    ]
    res["livepatch_fixed_cves"] = len((ss.get("livepatch") or {}).get("fixed_cves") or [])
    return res


def main():
    skip_update = "--skip-apt-update" in sys.argv
    data = {"schema": 1, "warnings": []}
    rc, out, _ = run(["hostname", "-f"])
    data["hostname"] = out.strip()
    data["kernel"] = os.uname()[2]
    data["arch"] = os.uname()[4]
    data["os"] = os_info()

    if not skip_update:
        rc, _, err = run(["apt-get", "-qq", "-o", "DPkg::Lock::Timeout=120", "update"], 600)
        if rc != 0:
            data["warnings"].append("apt-get update failed: " + err.strip()[-300:])
    data["apt_updated"] = not skip_update

    pro = which("pro") or which("ua")
    data["pro"] = pro_data(pro)

    rc, out, _ = run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev} ${Package} ${Version}\\n"])
    installed = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and f[0] == "ii":
            installed[f[1]] = f[2]
    data["installed_packages"] = len(installed) if rc == 0 else None
    data["package_sources"] = package_sources()

    upg, err = apt_upgradable()
    if err:
        data["warnings"].append(err)
    # Merge pro security-status entries, keyed by (package, pocket): the same package can have a
    # standard fix available now AND a newer ESM fix available with Pro (pending_attach/enable),
    # and ESM fixes are invisible to apt on unattached machines.
    by_key = {(p["n"], p["p"]): p for p in upg}
    for sp in data["pro"].get("security_packages", []):
        pocket = {"esm-infra": "esm-infra", "esm-apps": "esm-apps"}.get(sp["svc"], "security")
        e = by_key.get((sp["n"], pocket))
        if e is None and pocket == "security" and (sp["n"], "updates") in by_key:
            e = by_key[(sp["n"], "updates")]
            e["p"] = "security"
        if e is not None:
            e["st"] = sp["st"]
        else:
            e = {"n": sp["n"], "cur": installed.get(sp["n"]), "new": sp["new"], "p": pocket, "st": sp["st"]}
            upg.append(e)
            by_key[(sp["n"], pocket)] = e
    data["pro"].pop("security_packages", None)
    data["updates"] = upg
    pockets = {}
    for p in upg:
        pockets[p["p"]] = pockets.get(p["p"], 0) + 1
    data["pocket_counts"] = pockets
    # per-package counts of fixes only installable after attaching Pro / enabling a service
    needs_pro = {}
    for p in upg:
        if str(p.get("st", "")).startswith("pending"):
            needs_pro[p["p"]] = needs_pro.get(p["p"], 0) + 1
    data["needs_pro_counts"] = needs_pro

    data["reboot_required"] = os.path.exists("/var/run/reboot-required")
    try:
        with open("/var/run/reboot-required.pkgs") as f:
            data["reboot_required_pkgs"] = sorted(set(l.strip() for l in f if l.strip()))
    except Exception:
        data["reboot_required_pkgs"] = []

    def encode(d):
        raw = json.dumps(d, separators=(",", ":")).encode()
        return "PFA1:" + base64.b64encode(gzip.compress(raw)).decode()

    blob = encode(data)
    if len(blob) > MAX_OUTPUT and "--no-output-limit" not in sys.argv:  # keep counts, drop per-package detail
        data["updates"] = []
        data["updates_truncated"] = True
        blob = encode(data)
    print(blob)


if __name__ == "__main__":
    main()
