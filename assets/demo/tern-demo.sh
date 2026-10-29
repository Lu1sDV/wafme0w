#!/usr/bin/env bash
# Run from the repository root; requires Go, Bash and jq.
# Synthetic evidence only. Typing and pauses are presentation, not a benchmark.
set -euo pipefail
mode=${1:-all}
case "$mode" in all|evidence|automation) ;; *) exit 2 ;; esac
command -v jq >/dev/null
captures="$(pwd)/assets/demo/captures.jsonl"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go build -o "$work/wafme0w" ./cmd/wafme0w
export PATH="$work:$PATH"
cp "$captures" "$work/captures.jsonl"
cd "$work"
unset NO_COLOR
export TERM=xterm-256color

card() {
  printf '\033[3J\033[2J\033[H\033[1;36m  /\\_/\\   wafme0w\033[0m  /  %s\n' "$1"
  printf '\033[90m  SYNTHETIC CAPTURES  /  OFFLINE  /  REAL CLI OUTPUT\033[0m\n\n'
}
run() {
  printf '\033[36m$ \033[0m'
  for ((i=0; i<${#1}; i++)); do
    printf '%s' "${1:i:1}"
    sleep 0.012
  done
  printf '\n'
  eval "$1"
}
pause() {
  printf '\n\033[90m  %s  [Enter]\033[0m' "$1"
  read -r
}

if [[ "$mode" != all ]]; then
  card 'Real evidence. Two workflows.'
  pause 'Start recording'
fi

if [[ "$mode" == all ]]; then
  card 'Fingerprint the response. Keep the evidence.'
  printf '\n  01  READ       Named matches and supporting observations\n\n'
  printf '  02  AUTOMATE   JSONL for your existing pipelines\n\n'
  printf '  03  DECIDE     Incomplete evidence is not a clean negative\n\n'
  printf '\033[90m  Matches are evidence, not proof of enforcement.\033[0m\n'
  pause 'Start demo'
fi

if [[ "$mode" != automation ]]; then
  card '01 / Read the evidence'
  run 'wafme0w --evidence captures.jsonl'
  pause 'Next: machine-readable output'
fi
[[ "$mode" != evidence ]] || exit 0

card '02 / From terminal to pipeline'
if [[ "$mode" == automation ]]; then
  run "wafme0w --evidence captures.jsonl --jsonl --silent |
  jq -C '{target, state: .outcome.state}'"
else
  run "wafme0w --evidence captures.jsonl --jsonl --silent |
  jq -C '{target, state: .outcome.state, products: [.outcome.matches[]?.product]}'"
fi
pause 'Next: automation with an explicit safety signal'

card '03 / Save the report. Surface uncertainty.'
run 'wafme0w --evidence captures.jsonl --output results.json --silent --strict' && status=0 || status=$?
printf '\n\033[33m  Exit status: %s\033[0m\n\n' "$status"
test "$status" -eq 2
run "jq -r '.[] | [.target, .outcome.state] | @tsv' results.json"
printf '\n\033[32m  Report saved. Incomplete evidence remains visible.\033[0m\n\n'
printf '  A match is not proof of enforcement.\n  No match is not proof of absence.\n'
pause 'Demo complete'
