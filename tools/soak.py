#!/usr/bin/env python3
"""Exercise a trusted Linux CLI against owned mixed-failure loopback fixtures."""
import argparse
from collections import Counter
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import statistics
import subprocess
import threading
import time
from typing import cast
from urllib.parse import urlsplit


class Server(ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = True
    denied_origin: str
    denied_requests: list[str]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        kind = self.path.split('/')[1]
        body, headers, status = b'Owned ordinary origin fixture.', {}, 200
        if kind == 'slow':
            time.sleep(2)
        elif kind == 'drop':
            self.close_connection = True
            return
        elif kind == 'match':
            headers['CF-Ray'] = 'owned-fixture'
            headers['Server'] = 'cloudflare'
        elif kind == 'gzip':
            body, headers['Content-Encoding'] = gzip.compress(body), 'gzip'
        elif kind == 'truncated':
            body = b'x' * 8192
        elif kind == 'badgzip':
            headers['Content-Encoding'] = 'gzip'
        elif kind == 'redirect':
            status, headers['Location'] = 302, '/clean/redirected'
        elif kind == 'denied':
            status, headers['Location'] = 302, cast(Server, self.server).denied_origin + '/must-not-arrive'
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class DeniedHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        cast(Server, self.server).denied_requests.append(self.path)
        self.send_response(500)
        self.end_headers()


def sample_resources(pid):
    status = Path(f'/proc/{pid}/status').read_text()
    rss = next(int(line.split()[1]) for line in status.splitlines() if line.startswith('VmRSS:'))
    return {'seconds': time.monotonic(), 'rss_kib': rss,
            'fds': len(list(Path(f'/proc/{pid}/fd').iterdir()))}


def exercise(binary, root, origin, mode, duration):
    directory = root / mode
    directory.mkdir()
    command = [str(binary), '--jsonl', '--silent', '--strict', '--no-generic',
               '--concurrency=10', '--max-connections=30', '--max-body-bytes=4096',
               '--request-timeout=1s', '--target-timeout=5s', '--max-requests=18',
               '--rate=200', '--redirect-policy=same-origin', '--max-redirects=2']
    if mode != 'full':
        command.append('--' + mode)
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
    environment['NO_PROXY'] = '127.0.0.1'
    kinds = ('clean', 'match', 'gzip', 'truncated', 'badgzip', 'slow', 'drop', 'redirect', 'denied')
    sent, received, states = Counter(), Counter(), Counter()
    failures, samples = [], []
    pending = threading.Semaphore(64)
    started = time.monotonic()
    with (directory / 'results.jsonl').open('w') as output, (directory / 'stderr.txt').open('w') as stderr:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=stderr, text=True, env=environment)
        assert process.stdin is not None and process.stdout is not None
        stdout = process.stdout

        def consume():
            try:
                for line in stdout:
                    output.write(line)
                    row = json.loads(line)
                    target = row['target']
                    received[target] += 1
                    kind = urlsplit(target).path.split('/')[1]
                    outcome = row['outcome']
                    states[outcome['state']] += 1
                    expected = 'incomplete' if kind in ('truncated', 'badgzip', 'slow', 'drop', 'denied') else 'complete'
                    if outcome['state'] != expected:
                        raise AssertionError(f'{target}: state {outcome["state"]}, expected {expected}')
                    products = {match['product'] for match in outcome.get('matches', [])}
                    wanted = {'Cloudflare (Cloudflare Inc.)'} if kind == 'match' else set()
                    if products != wanted:
                        raise AssertionError(f'{target}: products {products}, expected {wanted}')
                    if expected == 'incomplete' and not outcome.get('diagnostics'):
                        raise AssertionError(f'{target}: missing failure diagnostic')
                    pending.release()
            except Exception as error:
                failures.append(str(error))
                process.kill()

        done = threading.Event()

        def observe():
            while not done.wait(.25):
                try:
                    samples.append(sample_resources(process.pid))
                except (OSError, StopIteration):
                    return

        consumer = threading.Thread(target=consume)
        observer = threading.Thread(target=observe)
        consumer.start()
        observer.start()
        watchdog = threading.Timer(duration + 90, process.kill)
        watchdog.start()
        try:
            index = 0
            while time.monotonic() - started < duration:
                if not pending.acquire(timeout=.5):
                    if failures:
                        raise RuntimeError(failures[0])
                    continue
                kind = kinds[index % len(kinds)]
                target = f'{origin}/{kind}/{index}'
                process.stdin.write(target + '\n')
                process.stdin.flush()
                sent[target] += 1
                index += 1
            process.stdin.close()
            code = process.wait(timeout=60)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            failures.append(str(error))
        finally:
            if process.poll() is None:
                process.kill()
            code = process.wait()
            watchdog.cancel()
            watchdog.join()
            consumer.join()
            done.set()
            observer.join()
            stdout.close()
            if not process.stdin.closed:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
    if code != 2:
        failures.append(f'strict mixed-failure exit {code}, expected 2')
    if sent != received or not all(any(f'/{kind}/' in target for target in received) for kind in kinds):
        failures.append('lost, duplicated, unexpected or unexercised targets')
    if not samples:
        failures.append('resource samples unavailable')
    warm = [sample for sample in samples if sample['seconds'] - started >= min(10, duration / 3)]
    first, last = warm[:max(1, len(warm)//3)], warm[-max(1, len(warm)//3):]
    growth = (statistics.median(sample['rss_kib'] for sample in last) -
              statistics.median(sample['rss_kib'] for sample in first)) if warm else None
    peak_rss = max((sample['rss_kib'] for sample in samples), default=0)
    peak_fds = max((sample['fds'] for sample in samples), default=0)
    if peak_rss > 192 * 1024 or peak_fds > 128 or growth is None or growth > 32 * 1024:
        failures.append('resource bound exceeded (192 MiB RSS, 128 FDs, 32 MiB warm median RSS growth)')
    report = {'mode': mode, 'command': command, 'exit_code': code,
              'wall_seconds': time.monotonic() - started, 'feed_seconds': duration,
              'sent': sum(sent.values()), 'received': sum(received.values()), 'states': dict(states),
              'peak_rss_kib': peak_rss, 'peak_fds': peak_fds, 'warm_rss_growth_kib': growth,
              'resource_limits': {'rss_kib': 192*1024, 'fds': 128, 'warm_rss_growth_kib': 32*1024},
              'failures': failures, 'samples': samples}
    (directory / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('samples', 'command')}), flush=True)
    if failures:
        raise RuntimeError('; '.join(failures))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='new evidence directory')
    parser.add_argument('--seconds', type=int, default=60, help='feed duration per mode, 5..3600')
    args = parser.parse_args()
    if not Path('/proc/self/status').exists() or not 5 <= args.seconds <= 3600:
        parser.error('requires Linux /proc and --seconds between 5 and 3600')
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    reports = []
    with Server(('127.0.0.1', 0), DeniedHandler) as denied, Server(('127.0.0.1', 0), Handler) as server:
        denied.denied_requests = []
        server.denied_origin = f'http://127.0.0.1:{denied.server_port}'
        workers = [threading.Thread(target=item.serve_forever, daemon=True) for item in (denied, server)]
        for worker in workers:
            worker.start()
        try:
            for mode in ('baseline', 'fast', 'full'):
                reports.append(exercise(binary, args.output, f'http://127.0.0.1:{server.server_port}', mode, args.seconds))
            if denied.denied_requests:
                raise AssertionError('redirect scope reached the denied origin')
        finally:
            server.shutdown()
            denied.shutdown()
            for worker in workers:
                worker.join()
    summary = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'scope': 'Owned Linux loopback soak; not Internet throughput, WAF accuracy or an indefinite leak proof.',
               'complete': True, 'denied_origin_requests': len(denied.denied_requests),
               'runs': [{key: value for key, value in report.items() if key != 'samples'} for report in reports]}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
