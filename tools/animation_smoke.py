#!/usr/bin/env python3
"""Exercise CLI logo animation with Linux PTYs and owned loopback fixtures.

    python3 tools/animation_smoke.py --binary ./wafmeow --output benchmarks/animation

The output directory must not exist. Each case retains bounded stdout/stderr and
its command; summary.json identifies the tested binary and every failure. No
external target is used, and no dependency beyond the standard library is needed.
Observation windows exercise redraw opportunities, not scan-speed requirements;
Go unit/synctest regressions verify that animation never delays acquisition.
"""

import argparse
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import selectors
import signal
import struct
import subprocess
import sys
import threading
import time


CSI = re.compile(rb'\x1b\[[0-?]*[ -/]*[@-~]')
SGR = re.compile(rb'\x1b\[[0-9;:]*m')
REDRAW = re.compile(rb'\x1b\[[0-9]*A')
BARE_RETURN = re.compile(rb'\r(?!\n)')
MAX_STREAM_BYTES = 128 * 1024
CASE_TIMEOUT = 6
# The startup animation is bounded to 540ms. Keep work outstanding past that
# interval to expose motion after the first result or under a disabling option.
OBSERVATION_SECONDS = 0.8


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def motion(data):
    # Human results may contain color styling, but no other escape or lone
    # carriage return may move, clear, or reset the terminal after a result.
    unstyled = SGR.sub(b'', data)
    return b'\x1b' in unstyled or BARE_RETURN.search(unstyled) is not None


def plain(data):
    return CSI.sub(b'', data).replace(b'\r\n', b'\n').decode('utf-8')


class Gate:
    def __init__(self):
        self.received = threading.Event()
        self.release = threading.Event()
        self.calls = 0


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.gates = {}
        self.lock = threading.Lock()

    def target(self, name):
        path = '/' + name
        gate = Gate()
        with self.lock:
            self.gates[path] = gate
        return f'http://127.0.0.1:{self.server_port}{path}', gate


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        with self.server.lock:
            gate = self.server.gates.get(self.path)
            if gate is not None:
                gate.calls += 1
        if gate is None:
            self.send_error(404)
            return
        gate.received.set()
        if not gate.release.wait(CASE_TIMEOUT * 2):
            return
        body = b'Owned ordinary response fixture.\n'
        try:
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


class Process:
    """Drain both outputs continuously and own every process/PTY we create."""

    def __init__(self, command, directory, *, stdout_tty=True, stdin_kind='null',
                 input_data=None, width=80, height=24, environment=None, stderr_tty=False):
        # Keep --help usable on unsupported hosts; these modules are Unix-only.
        import fcntl
        import pty
        import termios

        self.command = command
        self.presentation = {'stdout_tty': stdout_tty, 'stderr_tty': stderr_tty, 'stdin_kind': stdin_kind,
                             'columns': width, 'rows': height,
                             'environment_overrides': environment or {}}
        self.process = None
        self.ready = selectors.DefaultSelector()
        self.handles = []
        self.streams = {'stdout': bytearray(), 'stderr': bytearray()}
        env = {key: value for key, value in os.environ.items()
               if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
                                      'no_color', 'term', 'colorterm', 'force_color', 'clicolor_force')}
        env.update(TERM='xterm-256color', COLORTERM='truecolor', NO_PROXY='127.0.0.1')
        env.update(environment or {})

        def terminal(columns, rows):
            master, slave = pty.openpty()
            self.handles.extend([master, slave])
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))
            return master, slave

        require(not stderr_tty or stdout_tty, 'shared stderr requires terminal stdout')
        try:
            master, slave = terminal(width, height) if stdout_tty else (None, None)
            stdin = subprocess.DEVNULL
            stdin_slave = None
            if stdin_kind == 'pipe':
                stdin = subprocess.PIPE
            elif stdin_kind == 'tty':
                _, stdin_slave = terminal(80, 24)
                stdin = stdin_slave
            self.process = subprocess.Popen(
                command, cwd=directory, env=env, stdin=stdin,
                stdout=slave if stdout_tty else subprocess.PIPE,
                stderr=slave if stderr_tty else subprocess.PIPE,
                start_new_session=True,
            )
            for parent_copy in [slave, stdin_slave]:
                if parent_copy is not None:
                    os.close(parent_copy)
                    self.handles.remove(parent_copy)
            sources = [('stdout', master if stdout_tty else self.process.stdout)]
            if not stderr_tty:
                sources.append(('stderr', self.process.stderr))
            for name, source in sources:
                descriptor = source if isinstance(source, int) else source.fileno()
                os.set_blocking(descriptor, False)
                self.ready.register(descriptor, selectors.EVENT_READ, name)
            if stdin_kind == 'pipe' and input_data is not None:
                (directory / 'stdin.txt').write_bytes(input_data)
                self.process.stdin.write(input_data)
                self.process.stdin.close()
        except BaseException:
            self.close()
            raise

    def pump(self, timeout):
        for key, _ in self.ready.select(timeout):
            try:
                chunk = os.read(key.fd, 65536)
            except BlockingIOError:
                continue
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b''  # Linux PTY EOF.
            if not chunk:
                self.ready.unregister(key.fd)
                continue
            stream = self.streams[key.data]
            available = MAX_STREAM_BYTES - len(stream)
            stream.extend(chunk[:available])
            require(len(chunk) <= available, f'{key.data} exceeded {MAX_STREAM_BYTES} retained bytes')

    def wait_for(self, predicate, description, timeout=CASE_TIMEOUT):
        deadline = time.monotonic() + timeout
        while not predicate():
            remaining = deadline - time.monotonic()
            require(remaining > 0, f'timed out waiting for {description}')
            self.pump(min(0.05, remaining))
            if self.process.poll() is not None:
                self.pump(0)
                require(predicate(), f'exited {self.process.returncode} before {description}')

    def observe(self):
        deadline = time.monotonic() + OBSERVATION_SECONDS
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump(min(0.05, max(0, deadline - time.monotonic())))

    def finish(self, expected=0, timeout=CASE_TIMEOUT):
        deadline = time.monotonic() + timeout
        while self.process.poll() is None or self.ready.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'process or inherited output did not close')
            self.pump(min(0.05, remaining))
        require(self.process.returncode == expected,
                f'exit {self.process.returncode}, expected {expected}; stderr={bytes(self.streams["stderr"])[-2000:]!r}')

    def close(self):
        try:
            if self.process is not None:
                # This group was created by start_new_session; never signal a
                # caller's process group or search for unrelated processes.
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 2
                while self.ready.get_map() and time.monotonic() < deadline:
                    try:
                        self.pump(0.05)
                    except AssertionError:
                        # Already failed the output bound; drain/discard only
                        # until the owned process group exits.
                        continue
                self.process.wait(timeout=2)
        finally:
            self.ready.close()
            if self.process is not None:
                for stream in [self.process.stdin, self.process.stdout, self.process.stderr]:
                    if stream is not None:
                        stream.close()
            for descriptor in self.handles:
                os.close(descriptor)
            self.handles.clear()


def human_result(process, target):
    text = plain(process.streams['stdout'])
    # A shared stdout/stderr terminal also prints the target in the final
    # human summary. Count the result row, not every mention of the URL.
    row = '[ NO WAF MATCH ]  ' + target
    require(text.count(row) == 1, f'human result for {target} was missing or duplicated')


def terminal_cleanup(process):
    out = bytes(process.streams['stdout'])
    require(out.endswith(b'\n'), 'terminal output did not finish at a new line')
    require(not re.search(rb'\x1b\[\?(?:25|47|1047|1049)[hl]', out),
            'animation changed cursor visibility or the alternate screen')
    require(not motion(bytes(process.streams['stderr'])), 'animation wrote redraw controls to stderr')


def run_suite(binary, output):
    output.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    results = []
    with Server() as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        worker.start()

        def case(name, exercise):
            directory = output / f'{len(results)+1:02d}'
            directory.mkdir()
            (directory / 'catalogue.json').write_text('[]\n')
            processes, gates = [], []
            record = {'name': name, 'passed': False, 'error': None}

            def target(label):
                url, gate = server.target(f'{directory.name}/{label}')
                gates.append(gate)
                return url, gate

            def start(args, **kwargs):
                process = Process([str(binary), *args], directory, **kwargs)
                processes.append(process)
                return process

            try:
                exercise(start, target, directory)
                record['passed'] = True
            except Exception as error:
                record['error'] = f'{type(error).__name__}: {error}'
            finally:
                for gate in gates:
                    gate.release.set()
                for index, process in enumerate(processes):
                    try:
                        process.close()
                    except Exception as error:
                        record['passed'] = False
                        record['error'] = (record['error'] or '') + f'; cleanup: {error}'
                    prefix = '' if index == 0 else f'{index}-'
                    for stream, data in process.streams.items():
                        (directory / f'{prefix}{stream}.txt').write_bytes(data)
                    record.update(command=process.command, terminal=process.presentation,
                                  exit_code=process.process.returncode,
                                  stdout_bytes=len(process.streams['stdout']), stderr_bytes=len(process.streams['stderr']),
                                  redraws=len(REDRAW.findall(process.streams['stdout'])))
                record['requests'] = [gate.calls for gate in gates]
                (directory / 'case.json').write_text(json.dumps(record, indent=2) + '\n')
                results.append(record)
                print(('PASS ' if record['passed'] else 'FAIL ') + name + (': ' + record['error'] if record['error'] else ''), flush=True)

        base = ['--baseline', '--no-generic', '--fingerprints=catalogue.json', '--concurrency=2',
                '--max-connections=2', '--request-timeout=10s', '--target-timeout=12s', '--max-redirects=0']

        def animated(start, target, _directory, piped=False, shared=False):
            first, first_gate = target('first')
            second, second_gate = target('second')
            source = ['--target-file=-'] if piped else ['--target', first, '--target', second]
            kwargs = {'stdin_kind': 'pipe', 'input_data': (first + '\n' + second + '\n').encode()} if piped else {}
            if shared:
                kwargs['stderr_tty'] = True
            process = start([*base, *source], **kwargs)
            process.wait_for(lambda: first_gate.received.is_set() and second_gate.received.is_set(), 'both owned requests')
            process.wait_for(lambda: REDRAW.search(process.streams['stdout']), 'an animated redraw')
            first_gate.release.set()
            process.wait_for(lambda: first.encode() in process.streams['stdout'], 'the first human result')
            process.observe()
            second_gate.release.set()
            process.finish()
            human_result(process, first)
            human_result(process, second)
            out = bytes(process.streams['stdout'])
            position = out.rfind(b'\n', 0, out.index(first.encode())) + 1
            require(not motion(out[position:]), 'animation redrew after the first result')
            if shared:
                require(out.index(b'wafmeow') < out.index(b'RUN PLAN') < out.index(b'\x1b[11A'),
                        'logo must precede the two-line plan and first redraw')
                require(b'\x1b[2B' in out, 'shared redraw did not restore cursor below the plan')
            terminal_cleanup(process)
            require([first_gate.calls, second_gate.calls] == [1, 1], 'animation changed baseline request accounting')

        def disabled(start, target, directory, *, flags=(), environment=None, stdout_tty=True,
                     stdin_kind='null', width=80, height=24, kind='human'):
            url, gate = target('disabled')
            process = start([*base, '--target', url, *flags], environment=environment,
                            stdout_tty=stdout_tty, stdin_kind=stdin_kind, width=width, height=height)
            process.wait_for(gate.received.is_set, 'the owned request')
            process.observe()
            gate.release.set()
            process.finish()
            out, err = bytes(process.streams['stdout']), bytes(process.streams['stderr'])
            require(not motion(out) and not motion(err), 'disabled animation emitted redraw controls')
            if kind == 'jsonl':
                require(b'\x1b' not in out, 'JSONL contains ANSI output')
                rows = [json.loads(line) for line in out.splitlines()]
                require(len(rows) == 1 and rows[0]['target'] == url and rows[0]['schema_version'] == 1,
                        'JSONL result stream changed')
            elif kind == 'silent':
                require(not out and not err, 'silent scan emitted human output')
                rows = json.loads((directory / 'report.json').read_text())
                require(len(rows) == 1 and rows[0]['target'] == url, 'silent report lost its result')
            else:
                human_result(process, url)
                terminal_cleanup(process)
            require(gate.calls == 1, 'animation changed baseline request accounting')

        def informational(start, _target, _directory, flag):
            process = start([flag], stdin_kind='pipe')
            process.finish()
            out, err = bytes(process.streams['stdout']), bytes(process.streams['stderr'])
            require(not motion(out) and not motion(err), f'{flag} animated')
            require(not err, f'{flag} wrote stderr')
            require(bool(out), f'{flag} omitted output')
            if flag == '--help':
                require(b'--no-animation' in out, 'help omitted --no-animation')

        def cancelled(start, target, directory, signum):
            url, gate = target('cancelled')
            sentinel = b'previous report\n'
            (directory / 'report.json').write_bytes(sentinel)
            process = start([*base, '--target', url, '--output=report.json'])
            process.wait_for(gate.received.is_set, 'the owned request')
            process.wait_for(lambda: REDRAW.search(process.streams['stdout']), 'motion before cancellation')
            os.killpg(process.process.pid, signum)
            process.finish(expected=130)
            terminal_cleanup(process)
            require((directory / 'report.json').read_bytes() == sentinel, 'cancellation replaced the previous report')
            require(not list(directory.glob('.report.json-*')), 'cancellation leaked a temporary report')

        try:
            case('human TTY animates and stops before the first result', animated)
            case('piped target input still animates human TTY output', lambda *args: animated(*args, piped=True))
            case('combined stdout/stderr PTY preserves the plan below the cat',
                 lambda *args: animated(*args, shared=True))
            for name, kwargs in [
                ('--no-animation', {'flags': ['--no-animation']}),
                ('--no-colors', {'flags': ['--no-colors']}),
                ('NO_COLOR set', {'environment': {'NO_COLOR': '1'}}),
                ('NO_COLOR present but empty', {'environment': {'NO_COLOR': ''}}),
                ('TERM=dumb', {'environment': {'TERM': 'dumb'}}),
                ('TERM empty', {'environment': {'TERM': ''}}),
                ('narrow stdout', {'width': 30, 'stdin_kind': 'tty'}),
                ('short stdout', {'height': 4}),
                ('redirected stdout with terminal stdin', {'stdout_tty': False, 'stdin_kind': 'tty'}),
                ('JSONL on a terminal', {'flags': ['--jsonl'], 'kind': 'jsonl'}),
                ('silent on a terminal', {'flags': ['--silent', '--output=report.json'], 'kind': 'silent'}),
            ]:
                case(name + ' never animates', lambda *args, options=kwargs: disabled(*args, **options))
            for flag in ['--help', '--version', '--list']:
                case(flag + ' never animates', lambda *args, selected=flag: informational(*args, selected))
            for signum in [signal.SIGINT, signal.SIGTERM]:
                case(signum.name + ' during animation exits 130 and cleans up',
                     lambda *args, selected=signum: cancelled(*args, selected))
        finally:
            with server.lock:
                for gate in server.gates.values():
                    gate.release.set()
            server.shutdown()
            worker.join(timeout=2)
            require(not worker.is_alive(), 'owned loopback server did not stop')

    unchanged = digest == hashlib.sha256(binary.read_bytes()).hexdigest()
    summary = {'binary': str(binary), 'binary_sha256': digest, 'binary_unchanged': unchanged,
               'cases': len(results), 'passed': sum(record['passed'] for record in results),
               'all_passed': unchanged and all(record['passed'] for record in results),
               'scope': 'Linux PTYs and owned loopback only; no scan-speed timing assertion.',
               'results': results}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return 0 if summary['all_passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not sys.platform.startswith('linux'):
        parser.error('this actual-terminal suite requires Linux')
    binary = args.binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error('--binary must name an executable file')
    return run_suite(binary, args.output.resolve())


if __name__ == '__main__':
    sys.exit(main())
