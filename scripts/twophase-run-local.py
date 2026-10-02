#!/usr/bin/env python3
# Copyright (c) 2024 MIT Digital Currency Initiative,
#                    Federal Reserve Bank of Boston
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run a single-node 2PC system locally without Docker.

Reads a 2PC config file, rewrites every endpoint host to a local address,
then starts the locking shard, coordinator and sentinel as child processes.
Runs until interrupted (Ctrl-C), at which point the children are stopped.
"""

import argparse
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import time

ENDPOINT_RE = re.compile(r'^([A-Za-z0-9_]*endpoint)\s*=\s*"([^"]*)"\s*$')


def wait_for_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.25)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def rewrite_config(src: pathlib.Path, dst: pathlib.Path, host: str):
    """Replace the host part of every endpoint value with `host`.
    Returns a dict of endpoint-key -> port."""
    ports = {}
    out_lines = []
    for line in src.read_text().splitlines():
        m = ENDPOINT_RE.match(line)
        if m:
            key, value = m.groups()
            _, _, port = value.rpartition(':')
            if port.isdigit():
                ports[key] = int(port)
                line = f'{key}="{host}:{port}"'
        out_lines.append(line)
    dst.write_text('\n'.join(out_lines) + '\n')
    return ports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', default=os.environ.get('BUILD_DIR', 'build'),
                        help='build directory (default: build)')
    parser.add_argument('--config', default='2pc-compose.cfg',
                        help='2PC config to base the local config on')
    parser.add_argument('--ip', default='127.0.0.1',
                        help='local address to bind endpoints to')
    parser.add_argument('--timeout', type=float, default=60.0,
                        help='seconds to wait for each component to listen')
    args = parser.parse_args()

    repo = pathlib.Path(__file__).resolve().parent.parent
    build = pathlib.Path(args.build_dir)
    if not build.is_absolute():
        build = repo / build
    cfg_src = pathlib.Path(args.config)
    if not cfg_src.is_absolute():
        cfg_src = repo / cfg_src

    if not build.is_dir():
        print(f'error: build directory not found: {build}', file=sys.stderr)
        return 1
    if not cfg_src.is_file():
        print(f'error: config not found: {cfg_src}', file=sys.stderr)
        return 1

    rundir = build / 'twophase-local'
    rundir.mkdir(parents=True, exist_ok=True)
    cfg = rundir / 'config.cfg'
    ports = rewrite_config(cfg_src, cfg, args.ip)

    binary = {
        'shard': build / 'src/uhs/twophase/locking_shard/locking-shardd',
        'coordinator': build / 'src/uhs/twophase/coordinator/coordinatord',
        'sentinel': build / 'src/uhs/twophase/sentinel_2pc/sentineld-2pc',
    }
    for name, path in binary.items():
        if not path.is_file():
            print(f'error: missing binary: {path}', file=sys.stderr)
            return 1

    # (name, argv, port-key to wait for)
    plan = [
        ('shard', [str(binary['shard']), str(cfg), '0', '0'], 'shard0_0_endpoint'),
        ('coordinator', [str(binary['coordinator']), str(cfg), '0', '0'],
         'coordinator0_0_endpoint'),
        ('sentinel', [str(binary['sentinel']), str(cfg), '0'],
         'sentinel0_endpoint'),
    ]

    procs = []

    def stop(*_):
        for _, proc, _ in reversed(procs):
            if proc.poll() is None:
                proc.terminate()
        for _, proc, _ in reversed(procs):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        print('\nStopped.')
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    for name, argv, port_key in plan:
        log = open(rundir / f'{name}.log', 'ab')
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                cwd=rundir)
        procs.append((name, proc, port_key))
        if port_key in ports:
            if not wait_for_port(args.ip, ports[port_key], args.timeout):
                print(f'error: {name} did not start listening on '
                      f'{args.ip}:{ports[port_key]}', file=sys.stderr)
                stop()
        print(f'{name} running (pid {proc.pid})')

    print(f'\n2PC system running locally. Config: {cfg}')
    print(f'Logs: {rundir}/<component>.log')
    print('Example client command:')
    print(f'  {build}/src/uhs/client/client-cli {cfg} '
          'mempool0.dat wallet0.dat mint 10 5')
    print('Press Ctrl-C to stop.')

    # Wait until interrupted.
    try:
        while all(proc.poll() is None for _, proc, _ in procs):
            time.sleep(0.5)
        print('A component exited unexpectedly.', file=sys.stderr)
    except KeyboardInterrupt:
        pass
    stop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
