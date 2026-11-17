#!/usr/bin/env python3
"""Compare separately built broker_order_test binaries on a network-enabled host.

Each binary runs the same six MQTT version/QoS/window scenarios. Timing comes
from the test's publish-to-receive interval, not process startup or shutdown.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--minimal', type=Path)
    parser.add_argument('--fixed', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--messages', type=int, default=10000)
    parser.add_argument('--output', type=Path, required=True,
                        help='New directory for raw logs, metadata and results')
    args = parser.parse_args()
    if args.rounds < 1 or args.messages < 1:
        parser.error('rounds and messages must be positive')
    binaries = {'original': args.original}
    if args.minimal:
        binaries['minimal'] = args.minimal
    binaries['fixed'] = args.fixed
    binaries = {name: path.resolve(strict=True) for name, path in binaries.items()}
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = dict(platform=platform.platform(), cpu_count=os.cpu_count(),
                    rounds=args.rounds, messages_per_publisher=args.messages,
                    binaries={name: dict(path=str(path), sha256=hashlib.sha256(
                        path.read_bytes()).hexdigest()) for name, path in binaries.items()})
    (args.output / 'metadata.json').write_text(json.dumps(metadata, indent=2))
    pattern = re.compile(r'v(\d) qos(\d) window(\d+) publishers(\d+): '
                         r'(\d+) messages, (\d+) order errors, (\d+) ms')
    expected = {(v, q, w) for v in (4, 5) for q, w in ((0, 64), (1, 1), (1, 64))}
    records = []
    names = list(binaries)
    for publishers, parallel in ((1, None), (4, None), (4, 2)):
        for trial in range(args.rounds):
            order = names[trial % len(names):] + names[:trial % len(names)]
            for name in order:
                env = dict(os.environ, ORDER_TEST_MESSAGES=str(args.messages),
                           ORDER_TEST_PUBLISHERS=str(publishers))
                env.pop('ORDER_TEST_PARALLEL', None)
                if parallel is not None:
                    env['ORDER_TEST_PARALLEL'] = str(parallel)
                log = args.output / f'{name}-p{publishers}-ctx{parallel}-{trial}.log'
                with log.open('w') as stream:
                    run = subprocess.run([str(binaries[name])], env=env,
                                         stdout=stream, stderr=stream, timeout=240)
                rows = [tuple(map(int, row)) for row in pattern.findall(log.read_text())]
                if (run.returncode not in (0, 1) or len(rows) != 6 or
                        {row[:3] for row in rows} != expected):
                    raise RuntimeError(f'Incomplete/failed run: {log}')
                if name == 'fixed' and (run.returncode or any(row[5] for row in rows)):
                    raise RuntimeError(f'Fixed build failed ordering: {log}')
                for version, qos, window, pubs, count, errors, ms in rows:
                    if pubs != publishers or count != publishers * args.messages:
                        raise RuntimeError(f'Unexpected workload: {log}')
                    records.append(dict(variant=name, publishers=pubs, parallel=parallel,
                                        trial=trial, version=version, qos=qos, window=window,
                                        count=count, order_errors=errors, ms=ms))
                (args.output / 'records.json').write_text(json.dumps(records, indent=2))
                print(name, publishers, parallel, trial, 'complete', flush=True)
    summaries = []
    for publishers, parallel in ((1, None), (4, None), (4, 2)):
        for version, qos, window in sorted(expected):
            for name in names:
                selected = [r for r in records if (r['publishers'], r['parallel'],
                            r['version'], r['qos'], r['window'], r['variant']) ==
                            (publishers, parallel, version, qos, window, name)]
                times = [r['ms'] for r in selected]
                summaries.append(dict(variant=name, publishers=publishers, parallel=parallel,
                    version=version, qos=qos, window=window, median_ms=statistics.median(times),
                    min_ms=min(times), max_ms=max(times),
                    order_errors=sum(r['order_errors'] for r in selected)))
    (args.output / 'summary.json').write_text(json.dumps(summaries, indent=2))


if __name__ == '__main__':
    main()
