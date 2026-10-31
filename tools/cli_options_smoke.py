#!/usr/bin/env python3
"""Exercise CLI parsing and output contracts without live targets.

Run on Linux with Python 3 and an explicitly selected wafmeow binary. The suite
uses invalid URL schemes, saved synthetic captures, and private files/pipes; it
never sends a live HTTP request. Its literal-filename cases intentionally use
Linux path syntax, including quotes, backslashes, colons, and leading dashes.

The output directory must not exist. A frozen copy of the selected binary, its
SHA-256, per-case inputs/stdout/stderr, results.json, and summary.json are retained
for review. Use a path under benchmarks/ to keep these local artifacts ignored.
Exit status is zero only when every case and help-contract check passes.
"""

import argparse
import errno
import fcntl
import hashlib
import itertools
import json
import os
from pathlib import Path
import pty
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time

parser = argparse.ArgumentParser(description='Offline CLI behavior review against an explicitly selected binary.')
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True, help='Fresh output directory; existing directories are rejected.')
arguments = parser.parse_args()
if not __debug__:
    parser.error('assertion checks must be enabled; run without -O or PYTHONOPTIMIZE')
if not sys.platform.startswith('linux'):
    parser.error('this smoke suite requires Linux for its literal filename and pipe cases')
ROOT = arguments.output.resolve()
ROOT.mkdir(parents=True, exist_ok=False)
SOURCE_BINARY = arguments.binary.resolve()
BINARY = ROOT / 'wafmeow-reviewed'
shutil.copy2(SOURCE_BINARY, BINARY)
sha = hashlib.sha256(BINARY.read_bytes()).hexdigest()
TARGETS = 'invalid://from-file-one\r\n\ninvalid://from-file-two\n'
CAPTURES = json.dumps({'target': 'saved-fixture', 'evidence': [{'role': 'Normal', 'status_code': 200, 'body': 'b3JkaW5hcnk='}]}) + '\n'
BASE = ['--jsonl', '--silent', '--no-colors', '--concurrency=1', '--fingerprints=catalogue.json']
records = []


def run_terminal(command, directory, width, stdout_terminal):
    """Capture help through a real PTY, with one bounded process group."""
    master, slave = pty.openpty()
    process = None
    deadline = time.monotonic() + 5
    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, width, 0, 0))
        with (directory / 'stdout.txt').open('wb') as stdout, (directory / 'stderr.txt').open('wb') as stderr:
            process = subprocess.Popen(
                command, cwd=directory,
                stdin=subprocess.DEVNULL if stdout_terminal else slave,
                stdout=slave if stdout_terminal else stdout, stderr=stderr,
                start_new_session=True,
            )
            os.close(slave)
            slave = None
            if stdout_terminal:
                # Drain while the child runs: a full PTY buffer must not turn a
                # valid help page into a timeout. Linux reports PTY EOF as EIO.
                with selectors.DefaultSelector() as ready:
                    ready.register(master, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not ready.select(remaining):
                            raise subprocess.TimeoutExpired(command, 5)
                        try:
                            chunk = os.read(master, 65536)
                        except OSError as error:
                            if error.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        stdout.write(chunk)
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
    finally:
        if process is not None:
            # Also remove descendants on a failure before the child exits.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        if slave is not None:
            os.close(slave)
        os.close(master)
    return code, (directory / 'stdout.txt').read_bytes(), (directory / 'stderr.txt').read_bytes()


def case(name, args, *, expected=0, targets=None, stdin='', base=True, files=None, check=None, held_stdin=False, terminal_width=None, stdout_terminal=True):
    directory = ROOT / 'cases' / f'{len(records)+1:03d}'
    directory.mkdir(parents=True, exist_ok=False)
    fixtures = {'targets.txt': TARGETS, 'captures.jsonl': CAPTURES, 'catalogue.json': '[]'}
    fixtures.update(files or {})
    for filename, content in fixtures.items():
        path = directory / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    command = [str(BINARY), *(BASE if base else []), *args]
    started = time.monotonic()
    code = None
    error = None
    try:
        if terminal_width is not None:
            code, stdout, stderr = run_terminal(command, directory, terminal_width, stdout_terminal)
        elif held_stdin:
            with subprocess.Popen(command, cwd=directory, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                # communicate drains both output pipes while this duplicate
                # keeps stdin open and empty: an accidental input read blocks.
                held_writer = os.dup(process.stdin.fileno())
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    raise
                finally:
                    os.close(held_writer)
                code = process.returncode
        else:
            completed = subprocess.run(command, cwd=directory, input=stdin.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
        out, err = stdout.decode(), stderr.decode()
        (directory / 'stdout.txt').write_text(out)
        (directory / 'stderr.txt').write_text(err)
        assert code == expected, f'exit {code}, expected {expected}; stderr={err!r}'
        assert 'panic:' not in err and 'fatal error:' not in err, f'runtime failure: {err!r}'
        if expected == 1:
            assert not out, f'configuration/input rejection emitted stdout: {out[:200]!r}'
            assert err, 'missing error diagnostic'
        if targets is not None:
            results = [json.loads(line) for line in out.splitlines()]
            assert [result['target'] for result in results] == targets, f'targets={[result.get("target") for result in results]!r}, expected={targets!r}'
            assert all(result.get('schema_version') == 1 for result in results), 'not result JSONL'
            assert not err, f'silent mode wrote stderr: {err!r}'
        if check:
            check(directory, out, err)
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
    records.append({'name': name, 'args': args, 'expected_exit': expected, 'actual_exit': code, 'passed': error is None, 'error': error, 'seconds': time.monotonic()-started, 'directory': str(directory)})
    if error:
        print(f'FAIL {name}: {error}', flush=True)


def require(condition, message):
    assert condition, message


value_flags = [
    '--target', '--target-file', '--input', '--evidence', '--evidence-format', '--httpx-response-encoding',
    '--fingerprints', '--header', '--request-timeout', '--target-timeout', '--max-redirects', '--redirect-policy',
    '--allow-origin', '--probe-concurrency', '--concurrency', '--max-connections', '--rate', '--per-origin-rate',
    '--max-requests', '--max-body-bytes', '--max-response-header-bytes', '--max-target-evidence-bytes', '--output',
    '--diagnostics-journal', '--journal-batch-size', '--browser', '--browser-path', '--browser-timeout', '--browser-settle',
    '--browser-allow-origin', '--save-screenshots', '-t', '-I', '-O', '-H', '-c',
]
for flag in value_flags:
    case(f'missing value {flag}', [flag], expected=1)
    case(f'empty value {flag}', [flag + '='], expected=1)
    case(f'option as missing value {flag}', [flag, '--strict'], expected=1)
    case(f'delimiter as missing value {flag}', [flag, '--'], expected=1)

for flag in ['--fast', '--deep', '--baseline', '--no-generic', '--jsonl', '--strict', '--silent', '--no-colors', '--no-animation', '--no-warning', '--debug', '--list', '--version']:
    for value in ['true', 'false', '']:
        case(f'bool argument {flag}={value}', [f'{flag}={value}'], expected=1)

for flag in ['--tar', '--Target', '--TARGET', '--targets', '--target_file', '-i', '-o', '-T', '-C']:
    case(f'unknown spelling {flag}', [flag], expected=1)

for args in [
    ['--target=invalid://one', '--target=invalid://two'],
    ['-tinvalid://one', '-t', 'invalid://two'],
    ['-t=invalid://one', '--target', 'invalid://two'],
    ['-c2', '-tinvalid://one', '-tinvalid://two', '-c1'],
]:
    case('target accumulation ' + repr(args), args, targets=['invalid://one', 'invalid://two'], stdin='invalid://ignored\n')

for value in ['', ' ', '\t', '\n', '\r', 'invalid://one\ninvalid://two', 'invalid://one\r', '\ninvalid://one']:
    for first in [True, False]:
        args = ['--target', value, '-tinvalid://last'] if first else ['-tinvalid://first', '--target', value]
        case(f'non-single-line target {value!r} first={first}', args, expected=1)

case('target commas and percent escapes', ['-tinvalid://one/a,b?x=%0A&y=--input'], targets=['invalid://one/a,b?x=%0A&y=--input'])
case('target literal doublequotes', ['--target', '"invalid://quoted"'], targets=['"invalid://quoted"'])
case('direct target is never a file', ['--target=invalid://local'], files={'invalid:/local': TARGETS}, targets=['invalid://local'])
case('terminal delimiter', ['--target=invalid://one', '--'], targets=['invalid://one'])
case('positional after delimiter', ['--target=invalid://one', '--', 'invalid://two'], expected=1)
case('flag after delimiter is positional', ['--', '--target=invalid://one'], expected=1)
case('short valued flag consumes remainder', ['-c2tinvalid://one'], expected=1)

for spelling in ['--target-file', '--input', '-I']:
    case(f'file space form {spelling}', [spelling, 'targets.txt'], targets=['invalid://from-file-one', 'invalid://from-file-two'])
    case(f'file equals form {spelling}', [spelling+'=targets.txt'], targets=['invalid://from-file-one', 'invalid://from-file-two'])
    case(f'explicit stdin {spelling}', [spelling, '-'], stdin='invalid://stdin\n', targets=['invalid://stdin'])
    case(f'literal dash file {spelling}', [spelling, './-'], files={'-': TARGETS}, stdin='invalid://ignored\n', targets=['invalid://from-file-one', 'invalid://from-file-two'])
    for filename in ['"targets.txt', 'targets.txt"', '"targets.txt"', 'a\\b.txt', 'targets with spaces.txt', '--targets.txt']:
        case(f'literal path {spelling} {filename!r}', [spelling+'='+filename], files={filename: TARGETS}, targets=['invalid://from-file-one', 'invalid://from-file-two'])
case('short attached input', ['-Itargets.txt'], targets=['invalid://from-file-one', 'invalid://from-file-two'])
for first, second in itertools.product(['--target-file', '--input', '-I'], repeat=2):
    case(f'duplicate source {first} {second}', [first, 'targets.txt', second, 'targets.txt'], expected=1)
    case(f'distinct duplicate source {first} {second}', [first, 'targets.txt', second, 'other.txt'], files={'other.txt': 'invalid://other\n'}, expected=1)
for spelling in ['--target-file', '--input', '-I']:
    for other in [['--target=invalid://one'], ['--evidence=captures.jsonl'], ['--list'], ['--version']]:
        case(f'source conflict {spelling} {other}', [spelling, 'targets.txt', *other], expected=1)
case('duplicate evidence', ['--evidence=captures.jsonl', '--evidence=captures.jsonl'], expected=1)
case('evidence source remains offline', ['--evidence=captures.jsonl'], targets=['saved-fixture'])
case('JSONL target file is not autodetected evidence', ['--target-file=captures.jsonl'], targets=[CAPTURES.strip()])
case('evidence refuses target text', ['--evidence=targets.txt'], expected=1)

for flag in ['--concurrency', '--probe-concurrency', '--max-requests', '--max-connections', '--max-redirects', '--max-body-bytes', '--max-response-header-bytes', '--max-target-evidence-bytes']:
    for value in ['-1', '1.5', 'abc', '9223372036854775808']:
        case(f'invalid numeric {flag}={value}', ['--version', flag+'='+value], expected=1, base=False)
for value in ['0', '65537', '2147483648', '9223372036854775807']:
    case(f'concurrency rejected {value}', ['--version', '--concurrency='+value], expected=1, base=False)
for value in ['1', '65536']:
    case(f'concurrency validation boundary {value}', ['--version', '--concurrency='+value], base=False)
for flag in ['--rate', '--per-origin-rate']:
    for value in ['-1', 'NaN', '+Inf', '-Inf', '1e999', 'abc']:
        case(f'invalid rate {flag}={value}', ['--version', flag+'='+value], expected=1, base=False)
for flag in ['--request-timeout', '--target-timeout']:
    for value in ['0s', '-1s', '30', 'garbage']:
        case(f'invalid duration {flag}={value}', ['--version', flag+'='+value], expected=1, base=False)
for flag, value in [('--browser', 'wrong'), ('--redirect-policy', 'wrong'), ('--evidence-format', 'wrong')]:
    case(f'invalid choice {flag}', ['--version', flag+'='+value], expected=1, base=False)

for args in [
    ['--browser-path=missing'], ['--browser-timeout=30s'], ['--browser-settle=2s'], ['--save-screenshots=images'],
    ['--browser-allow-origin=https://fixture.invalid'], ['--journal-batch-size=1'], ['--fast', '--probe-concurrency=2'],
    ['--baseline', '--probe-concurrency=2'], ['--fast', '--baseline'], ['--fast', '--deep'],
    ['--deep', '--baseline'], ['--evidence=-', '--deep'], ['--deep', '--version'], ['--evidence-format=native'],
    ['--httpx-response-encoding=text'], ['--allow-origin=not-an-origin'],
]:
    case('invalid dependency ' + repr(args), ['--target=invalid://one', *args], expected=1)
for mode in ['--help', '--version', '--list']:
    case('browser-independent info '+mode, [mode, '--browser=screenshot', '--browser-path=/missing/browser'], base=False)
    case('informational command ignores blocked stdin '+mode, [mode], base=False, held_stdin=True)
case('direct target does not read held stdin', ['--target=invalid://one'], targets=['invalid://one'], held_stdin=True)
case('file input does not read held stdin', ['--target-file=targets.txt'], targets=['invalid://from-file-one', 'invalid://from-file-two'], held_stdin=True)

for value in ['"Accept: text/plain, application/json"', '"X-Tag: say ""hello"""', 'X-Tag: value', 'X-Tag:']:
    for form in [['-H', value], ['-H'+value], ['-H='+value]]:
        case('header spelling '+repr(form), ['--target=invalid://one', *form], targets=['invalid://one'])
for value in ['NoColon', '', 'X-Tag: first\nSecond: injected', '"X-Tag: unclosed']:
    case('invalid header '+repr(value), ['--target=invalid://one', '-H', value], expected=1)

for filename in ['"report.json', 'report.json"', '"report.json"', 'a\\b.json', '--report.json', '-']:
    for form in [['-O', filename], ['-O='+filename], ['-O'+filename]]:
        # A leading-dash path must use an attached/equals value, or ./ prefix.
        if form == ['-O', filename] and filename.startswith('--'):
            continue
        case('literal output '+repr(form), ['--target=invalid://one', *form], targets=['invalid://one'], check=lambda d,o,e,n=filename: require((d/n).is_file(), f'literal output path {n!r} missing'))
for spelling in ['--target-file', '--input', '-I']:
    for sink in ['--output', '--diagnostics-journal']:
        case(f'file collision {spelling} {sink}', [spelling, 'targets.txt', sink, 'targets.txt'], expected=1, check=lambda d,o,e: require((d/'targets.txt').read_bytes() == TARGETS.encode(), 'input modified'))

def check_json_report(directory, out, err):
    records = [json.loads(line) for line in out.splitlines()]
    report = json.loads((directory/'report.json').read_text())
    require(report == records, 'atomic JSON report differs from stdout results')

case('strict emits and publishes repeated targets', ['--target=invalid://one', '--target=invalid://two', '--strict', '--output=report.json'], expected=2, targets=['invalid://one', 'invalid://two'], check=check_json_report)

help_result = subprocess.run([str(BINARY), '--help'], capture_output=True, text=True, timeout=5)
help_text = help_result.stdout
help_normalized = ' '.join(help_text.split())
help_checks = {
    'exit_zero': help_result.returncode == 0,
    'stderr_empty': help_result.stderr == '',
    'groups': all(word+':' in help_text for word in ['Input', 'Scan modes', 'Output', 'HTTP requests', 'Rate and concurrency', 'Evidence limits', 'Offline import and matching', 'Diagnostics and journals', 'Browser', 'Information']),
    'canonical_and_alias': '--target-file=FILE' in help_text and '--input=FILE' in help_text,
    'short_flags': all('-'+flag+',' in help_text for flag in ['t', 'I', 'O', 'H', 'c']),
    'machine_output_boundary': '--jsonl' in help_text and '- is a literal file' in help_normalized,
    'default_timeout': '(default: 5s)' in help_text,
    'default_concurrency': '(default: 20)' in help_text,
    'explicit_stdin': 'piped stdin supplies target URLs' in help_normalized,
    'exit_codes': all(code in help_text for code in ['Exit codes:', '  0 ', '  1 ', '  2 ', '  130 ']),
    'tasks_before_reference': 0 <= help_text.find('wafmeow --target URL --fast') < help_text.find('--target=URL'),
    'accurate_import_limit': 'live responses and httpx imports' in help_normalized,
    'deadline_waits': 'including local rate/connection waits' in help_normalized,
    'empty_and_strict_contracts': 'Empty input succeeds' in help_normalized and 'Matches alone do not fail' in help_normalized,
    'capture_report_distinction': 'captures, not result reports' in help_normalized,
}


def check_terminal_help(directory, out, err, width):
    require(not err, f'terminal help wrote stderr: {err!r}')
    require(' '.join(out.split()) == help_normalized, 'terminal help lost or changed content')
    for number, line in enumerate(out.splitlines(), 1):
        require(len(line) <= width, f'help line {number} exceeds {width} columns ({len(line)}): {line}')
    if width == 80:
        require(out.splitlines() == help_text.splitlines(), '80-column terminal help differs from the 80-column pipe fallback')


for width in [60, 80]:
    for stdout_terminal in [True, False]:
        placement = 'stdout PTY' if stdout_terminal else 'redirected stdout with stdin PTY'
        case(f'help at {width} columns via {placement}', ['--help'], base=False,
             terminal_width=width, stdout_terminal=stdout_terminal,
             check=lambda d, o, e, w=width: check_terminal_help(d, o, e, w))

(ROOT/'help.txt').write_text(help_text)
(ROOT/'help-stderr.txt').write_text(help_result.stderr)
summary = {
    'source_binary': str(SOURCE_BINARY), 'reviewed_binary_sha256': sha,
    'cases': len(records), 'passed': sum(item['passed'] for item in records),
    'failed': [item for item in records if not item['passed']], 'help_checks': help_checks,
    'all_passed': all(item['passed'] for item in records) and all(help_checks.values()),
}
(ROOT/'results.json').write_text(json.dumps(records, indent=2)+'\n')
(ROOT/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2))
sys.exit(0 if summary['all_passed'] else 1)
