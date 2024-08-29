#!/usr/bin/env bash

cd "$(dirname "$0")/.." || exit 1

EVENT_TABLE="api/flags_table.c"

(cat << EOF
use falco_event_derive::event_flags;

event_flags! {
EOF

cat api/flag_types

echo

sed -n '/ppm_name_value/,$p' < $EVENT_TABLE | grep -v '^#' | uniq

echo '}') > src/fields/event_flags.rs

rustfmt src/fields/event_flags.rs