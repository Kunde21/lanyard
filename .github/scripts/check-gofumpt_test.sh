#!/usr/bin/env bash

set -eu

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check_script="$script_dir/check-gofumpt.sh"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

write_formatter() {
	local name="$1"
	local output="$2"
	local status="$3"
	printf '#!/usr/bin/env bash\nprintf "%%s" %q\nexit %q\n' "$output" "$status" >"$test_dir/$name"
	chmod +x "$test_dir/$name"
}

mkdir "$test_dir/formatted" "$test_dir/unformatted"
printf 'package sample\n\nfunc value() int { return 1 }\n' >"$test_dir/formatted/formatted.go"
printf 'package sample\nfunc value()int{return 1}\n' >"$test_dir/unformatted/unformatted.go"

if ! bash "$check_script" "$test_dir/formatted"; then
	printf 'formatted source should pass\n' >&2
	exit 1
fi
if bash "$check_script" "$test_dir/unformatted" >/dev/null 2>&1; then
	printf 'unformatted source should fail\n' >&2
	exit 1
fi

if GOFUMPT_BIN="$test_dir/missing" bash "$check_script" "$test_dir/formatted" >/dev/null 2>&1; then
	printf 'missing formatter should fail\n' >&2
	exit 1
fi

write_formatter failing '' 42
if GOFUMPT_BIN="$test_dir/failing" bash "$check_script" "$test_dir/formatted" >/dev/null 2>&1; then
	printf 'failing formatter should fail\n' >&2
	exit 1
fi
