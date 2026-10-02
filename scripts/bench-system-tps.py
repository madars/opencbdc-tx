#!/usr/bin/env python3
"""Robust max-throughput search for a local 2PC system.

Starts shard/coordinator/sentinel with a freshly rewritten config (unique ports
per run), drives N load generators for a fixed duration, and reports aggregate
confirmed TPS. Cleans up child processes and verifies each stage.
"""

import argparse
import glob
import os
import re
import signal
import socket
import subprocess
import sys
import time
import pathlib

ENDPOINT_RE = re.compile(r'^([A-Za-z0-9_]*endpoint)\s*=\s*"([^"]*)"\s*$')

PORT_KEYS = {
    'sentinel0_endpoint': 0,
    'coordinator0_0_endpoint': 1,
    'coordinator0_0_raft_endpoint': 2,
    'shard0_0_endpoint': 3,
    'shard0_0_raft_endpoint': 4,
    'shard0_0_readonly_endpoint': 5,
}


def wait_port(host, port, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.05)
    return False


def write_config(src, dst, base, inout, mint):
    ports = {}
    out = []
    for line in src.read_text().splitlines():
        m = ENDPOINT_RE.match(line)
        if m and m.group(1) in PORT_KEYS:
            key = m.group(1)
            port = base + PORT_KEYS[key]
            ports[key] = port
            line = f'{key}="127.0.0.1:{port}"'
        out.append(line)
    out += [
        f'loadgen_sendtx_input_count={inout}',
        f'loadgen_sendtx_output_count={inout}',
        'loadgen_fixed_tx_rate=1.0',
        f'initial_mint_count={mint}',
        'initial_mint_value=100',
    ]
    dst.write_text('\n'.join(out) + '\n')
    return ports


def tail(path, n=6):
    try:
        lines = path.read_text().splitlines()[-n:]
        return '\n'.join('    ' + l for l in lines)
    except Exception:
        return '    <no log>'


def terminate(procs, name):
    for p in procs:
        if p.poll() is None:
            p.terminate()
    end = time.monotonic() + 5
    for p in procs:
        if p.poll() is None:
            try:
                p.wait(timeout=max(0.1, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                p.kill()
    for p in procs:
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def read_cpu(pid):
    try:
        with open(f'/proc/{pid}/stat') as f:
            parts = f.read().split()
        return (int(parts[13]) + int(parts[14])) / os.sysconf('SC_CLK_TCK')
    except Exception:
        return None


def run_point(build, repo, src_cfg, ngen, inout, duration, run_idx, mint,
              verbose, cpu=False):
    rundir = repo / 'run'
    if rundir.exists():
        subprocess.run(['rm', '-rf', str(rundir)], check=False)
    rundir.mkdir(parents=True)
    logdir = rundir / 'logs'
    logdir.mkdir()

    base = 30000 + run_idx * 20
    cfg = rundir / 'config.cfg'
    ports = write_config(src_cfg, cfg, base, inout, mint)

    sentinel_bin = build / 'src/uhs/twophase/sentinel_2pc/sentineld-2pc'
    if not sentinel_bin.exists():
        sentinel_bin = build / 'src/uhs/twophase/sentinel_2pc/sentineld'

    plan = [
        ('shard', build / 'src/uhs/twophase/locking_shard/locking-shardd',
         [str(cfg), '0', '0'], ports['shard0_0_endpoint']),
        ('coordinator', build / 'src/uhs/twophase/coordinator/coordinatord',
         [str(cfg), '0', '0'], ports['coordinator0_0_endpoint']),
        ('sentinel', sentinel_bin, [str(cfg), '0'], ports['sentinel0_endpoint']),
    ]

    servers = []
    for name, binary, args, port in plan:
        assert binary.exists(), f'missing binary {binary}'
        lf = open(logdir / f'{name}.log', 'wb')
        p = subprocess.Popen([str(binary)] + args, cwd=rundir,
                             stdout=lf, stderr=subprocess.STDOUT)
        servers.append((name, p, port, logdir / f'{name}.log'))
        if not wait_port('127.0.0.1', port, 20):
            print(f'  ! {name} failed to listen on {port}', file=sys.stderr)
            print(tail(logdir / f'{name}.log'), file=sys.stderr)
            terminate([p for _, p, _, _ in servers], name)
            return None
        if p.poll() is not None:
            print(f'  ! {name} exited during startup', file=sys.stderr)
            print(tail(logdir / f'{name}.log'), file=sys.stderr)
            terminate([q for _, q, _, _ in servers], name)
            return None

    loads = []
    for g in range(ngen):
        lf = open(logdir / f'loadgen{g}.log', 'wb')
        p = subprocess.Popen(
            [str(build / 'tools/bench/twophase-gen'), str(cfg), str(g)],
            cwd=rundir, stdout=lf, stderr=subprocess.STDOUT)
        loads.append(p)

    tracked = [(name, p) for name, p, _, _ in servers] \
        + [(f'loadgen{g}', p) for g, p in enumerate(loads)]
    before = {name: read_cpu(p.pid) for name, p in tracked} if cpu else None
    time.sleep(duration)
    if cpu:
        after = {name: read_cpu(p.pid) for name, p in tracked}
        used = []
        for name, _ in tracked:
            if before.get(name) is not None and after.get(name) is not None:
                used.append((name, (after[name] - before[name]) / duration))
        total = sum(c for _, c in used)
        detail = '  '.join(f'{n}={c:.2f}' for n, c in used)
        print(f'    cpu cores: total={total:.2f}/4  {detail}')
        sys.stdout.flush()
    terminate(loads, 'loadgen')

    ts = []
    for fn in glob.glob(str(rundir / 'tx_samples_*.txt')):
        with open(fn) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    ts.append(int(parts[0]))

    # sanity: no fatal errors in logs
    for name, p, _, logpath in servers:
        txt = logpath.read_text(errors='ignore') if logpath.exists() else ''
        if 'FATAL' in txt:
            print(f'  ! {name} logged FATAL', file=sys.stderr)
            print(tail(logpath), file=sys.stderr)

    terminate([p for _, p, _, _ in servers], 'servers')

    if len(ts) < 2:
        return 0.0, len(ts)
    span = (max(ts) - min(ts)) / 1e9
    tps = (len(ts) - 1) / span if span > 0 else 0.0
    return tps, len(ts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo',
                    default=str(pathlib.Path(__file__).resolve().parent.parent))
    ap.add_argument('--build', default=None)
    ap.add_argument('--config', default='2pc-compose.cfg')
    ap.add_argument('--tag', default='sys')
    ap.add_argument('--duration', type=float, default=10.0)
    ap.add_argument('--mint', type=int, default=4000)
    ap.add_argument('--points', default='1x1,2x1,4x1,2x2,4x2')
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--cpu', action='store_true')
    args = ap.parse_args()

    repo = pathlib.Path(args.repo).resolve()
    build = pathlib.Path(args.build).resolve() if args.build else repo / 'build'
    src_cfg = repo / args.config

    print(f'[{args.tag}] repo={repo} build={build}')
    sys.stdout.flush()

    points = []
    for tok in args.points.split(','):
        n, k = tok.lower().split('x')
        points.append((int(n), int(k)))

    best = (0.0, None)
    for i, (ngen, inout) in enumerate(points):
        r = run_point(build, repo, src_cfg, ngen, inout, args.duration, i,
                      args.mint, args.verbose, args.cpu)
        if r is None:
            print(f'[{args.tag}] gens={ngen} in/out={inout}: FAILED')
            continue
        tps, n = r
        print(f'[{args.tag}] gens={ngen} in/out={inout}: {n:7d} tx -> {tps:8.0f} tx/s')
        sys.stdout.flush()
        if tps > best[0]:
            best = (tps, (ngen, inout))
    print(f'[{args.tag}] BEST: {best[0]:.0f} tx/s at gens={best[1][0]} in/out={best[1][1]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
