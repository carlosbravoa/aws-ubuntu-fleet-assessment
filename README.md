# pro-fleet-assess

Read-only Ubuntu Pro / patch-status assessment of an AWS fleet, over **SSM Run Command**
(default) or **SSH**. One entry point, one report, one collector:

```
pro_fleet_assess.py   entry point: shared flags, report, table/CSV/JSON
transport_ssm.py      SSM discovery + Run Command execution
transport_ssh.py      SSH discovery (EC2 or --host list) + execution
common.py             helpers shared by the entry point and both transports
collector.py          what actually runs on each machine
```

Pick the transport with `--transport ssm|ssh` (default `ssm`). Shared flags (`--limit`, `--details`,
`--json`, `--csv`, `--tag`, region selection, ...) work the same on both; flags belonging to the other
transport are rejected rather than ignored.

For every **Ubuntu machine** it reaches it reports:

- Ubuntu Pro: attached or not, enabled services, account/contract/expiry (from `pro status`)
- Pending updates per pocket: `security`, `updates` (non-security), `esm-infra`, `esm-apps`,
  `backports`/`proposed`/third-party (`other`). ESM security fixes available with an Ubuntu Pro
  subscription are flagged as **needs Pro** (`pending_attach` / `pending_enable` from `pro security-status`),
  and the summary shows how many instances would benefit from Ubuntu Pro.
- Reboot required (plus the packages that triggered it; livepatch-aware)
- Kernel (`uname -r`), OS (`lsb_release -a`)
- Installed package count and sources (main / restricted / universe / multiverse / ESM / third-party
  sites / unknown-local)
- Coverage gaps: machines skipped (offline / not Ubuntu / unreachable) and, over SSM, running EC2
  instances with no SSM agent

## Usage

```sh
pip install -r requirements.txt
./pro_fleet_assess.py                             # region from your AWS config
./pro_fleet_assess.py -r us-east-1 -r eu-west-1   # specific regions
./pro_fleet_assess.py --all-regions --details     # every region + per-package tables
./pro_fleet_assess.py -a --json report.json --csv report.csv
./pro_fleet_assess.py -r us-east-1 --tag Env=prod -i i-0123456789abcdef0
./pro_fleet_assess.py -a --limit 50                # assess at most 50 instances in total
./pro_fleet_assess.py -a --max-concurrency 10%     # gentler rollout across a large fleet

# over SSH, for machines with no SSM agent
./pro_fleet_assess.py --transport ssh -k ~/.ssh/key.pem -r us-east-1
./pro_fleet_assess.py --transport ssh -k key.pem --all-regions --tag Env=prod --private-ip -J ubuntu@bastion
./pro_fleet_assess.py --transport ssh -k key.pem -H 10.0.0.5 -H admin@db1:2222 --hosts-file hosts.txt
```

### Transports

| | `--transport ssm` (default) | `--transport ssh` |
|---|---|---|
| Needs | SSM agent + `AmazonSSMManagedInstanceCore` | SSH key, reachable port, passwordless `sudo` |
| Targets | online Ubuntu managed nodes | running EC2 instances, or `-H/--hosts-file` (no AWS needed) |
| Also reports | running EC2 instances missing from SSM | — |
| Output limit | per-package detail dropped over ~24 KB | no limit (`--no-output-limit`) |
| `--workers` | regions in parallel (default 8) | hosts in parallel (default 20) |

### Large fleets

- `--limit N` caps how many instances are assessed in total. Regions are filled in the order given
  (or alphabetically with `--all-regions`); instances beyond the cap are listed as skipped, so the
  report still shows the full fleet size.
- `--max-concurrency` (default `50`) is how many instances SSM runs the collector on at once, per
  batch of 50 sent instance ids. Accepts a count or a percentage.
- `--max-errors` (default `100%`) is SSM's `MaxErrors`. The default means a failing instance never
  aborts the rest of the batch; failures are reported per instance instead. AWS's own default is `0`,
  which would stop a batch after the first failure.
- `--workers` is how many regions (SSM) or hosts (SSH) run in parallel.

By default each instance runs `apt-get update` first so pending-update counts are current;
`--skip-apt-update` avoids touching apt state at all (faster, may under-report).
Nothing is installed or upgraded.

## How it works

`collector.py` runs as root with the system `python3` (compatible down to xenial) and prints one
compressed JSON line that the driver decodes. Over SSM it is shipped gzip+base64 inside an
`AWS-RunShellScript` command; over SSH it is streamed to `sudo python3 -` and nothing is written to
disk on the host. Over SSM, per-package detail is dropped automatically if it would exceed the 24 KB
output limit (counts stay complete); over SSH the full list is always returned.

## IAM permissions needed (caller)

SSM transport: `ssm:DescribeInstanceInformation`, `ssm:SendCommand`, `ssm:ListCommandInvocations`,
`ssm:GetCommandInvocation`, `ec2:DescribeInstances`, `ec2:DescribeRegions`. Instances need the SSM
agent and an instance profile with `AmazonSSMManagedInstanceCore`.

SSH transport: `ec2:DescribeInstances` and `ec2:DescribeRegions` for discovery (none at all when
targets come from `-H` / `--hosts-file`), plus network reachability and passwordless `sudo` on each host.

## SSH transport

Runs `collector.py` with `sudo -n python3 -`, so the SSH user needs passwordless sudo (as `ubuntu` has on
cloud images).

```sh
# EC2 discovery (running instances, public IPs), optionally filtered by key pair / tag / id
./pro_fleet_assess.py --transport ssh -k ~/keys/myKeyPair.pem -r us-east-1 --key-name myKeyPair
./pro_fleet_assess.py --transport ssh -k key.pem --all-regions --tag Env=prod -p 2222 -u ubuntu
# private subnets through a bastion
./pro_fleet_assess.py --transport ssh -k key.pem -r eu-west-1 --private-ip -J ubuntu@bastion.example.com
# explicit hosts (no AWS API calls): [user@]host[:port], or one per line in a file
./pro_fleet_assess.py --transport ssh -k key.pem -H 10.0.0.5 -H admin@db1:2222 --hosts-file hosts.txt
```

`pro_fleet_assess_ssh.py` is kept as a deprecated alias: it injects `--transport ssh` and forwards, so
older command lines keep working.

Host keys are accepted on first use (`StrictHostKeyChecking=accept-new`); `--no-host-key-check` skips
verification and leaves `known_hosts` untouched (handy for short-lived instances). Extra ssh options go
through `-o`. Explicit-host mode makes no AWS API calls at all.
