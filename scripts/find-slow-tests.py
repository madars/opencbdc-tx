#!/usr/bin/env python3
# Copyright (c) 2024 MIT Digital Currency Initiative,
#                    Federal Reserve Bank of Boston
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run a GoogleTest binary one test case at a time with a per-test timeout.

Diagnostic tool for tests that hang or run unexpectedly long, which otherwise
look like a stalled suite. It copies the repository's test config files into
the build directory first, the same way scripts/test.sh does.

Examples:
    # Every unit test, 30s timeout each
    ./scripts/find-slow-tests.py

    # Just a suite, with a shorter timeout
    ./scripts/find-slow-tests.py --filter 'sentinel_2pc_test.*' --timeout 10

    # The integration tests
    ./scripts/find-slow-tests.py --binary tests/integration/run_integration_tests
"""

import argparse
import pathlib
import shutil
import subprocess
import sys
import time


def list_tests(binary: pathlib.Path, cwd: pathlib.Path, timeout: float):
    proc = subprocess.run([str(binary), '--gtest_list_tests'],
                          cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)
    tests = []
    suite = ''
    for line in proc.stdout.splitlines():
        if line.startswith('Running main()'):
            continue
        if not line.startswith(' '):
            suite = line.strip().rstrip('.')
        else:
            name = line.strip()
            if suite and name:
                tests.append(f'{suite}.{name}')
    return tests


def main() -> int:
    repo = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir',
                        default=str(repo / 'build'),
                        help='build directory (default: build)')
    parser.add_argument('--binary',
                        default='tests/unit/run_unit_tests',
                        help='test binary relative to the build directory')
    parser.add_argument('--filter', default='*',
                        help='GoogleTest filter (default: *)')
    parser.add_argument('--timeout', type=float, default=30.0,
                        help='per-test timeout in seconds (default: 30)')
    parser.add_argument('--list', action='store_true',
                        help='only list the matching tests')
    args = parser.parse_args()

    build = pathlib.Path(args.build_dir)
    if not build.is_absolute():
        build = repo / build
    binary = build / args.binary
    if not binary.is_file():
        print(f'error: no such test binary: {binary}', file=sys.stderr)
        return 1

    # Ensure config files are where the tests expect them.
    for pattern in ('tests/unit/**/*.cfg', 'tests/integration/*.cfg'):
        for cfg in repo.glob(pattern):
            shutil.copy(cfg, build)

    tests = list_tests(binary, build, args.timeout)
    if args.filter != '*':
        import fnmatch
        tests = [t for t in tests if fnmatch.fnmatch(t, args.filter)]

    if args.list:
        print('\n'.join(tests))
        return 0

    if not tests:
        print('No tests matched.', file=sys.stderr)
        return 1

    n_pass = n_fail = n_slow = 0
    slow = []
    for test in tests:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [str(binary), f'--gtest_filter={test}'],
                cwd=build, capture_output=True, text=True,
                timeout=args.timeout)
            elapsed = time.monotonic() - start
            if proc.returncode == 0:
                n_pass += 1
                status = 'ok'
            else:
                n_fail += 1
                status = 'FAIL'
                print(f'--- {test} output ---')
                print(proc.stdout[-2000:], proc.stderr[-2000:])
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            n_slow += 1
            status = 'TIMEOUT'
            slow.append(test)
        if status != 'ok' or elapsed > args.timeout / 2:
            print(f'{status:8s} {elapsed:8.2f}s  {test}', flush=True)

    print(f'\n{n_pass} passed, {n_fail} failed, {n_slow} timed out '
          f'(timeout {args.timeout:g}s)')
    if slow:
        print('Timed out:')
        for test in slow:
            print(f'  {test}')
    return 1 if (n_fail or n_slow) else 0


if __name__ == '__main__':
    sys.exit(main())
