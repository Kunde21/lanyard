#!/usr/bin/env bash

set -u

formatter="${GOFUMPT_BIN:-gofumpt}"
target="${1:-.}"
if ! format_output="$("$formatter" -l "$target")"; then
	printf 'gofumpt formatting check failed\n' >&2
	exit 1
fi
if [[ -n "$format_output" ]]; then
	printf '%s\n' "$format_output"
	exit 1
fi
