#!/usr/bin/env bash

cd "$(dirname "$0")/.." || exit 1

EVENT_TABLE="api/event_table.c"

(cat << EOF
use falco_event_derive::event_info;

event_info! {
EOF

awk '
/^};$/ { do_print = 0; }

do_print == 1 {
  $0 = gensub(/DIRFD_PARAM\(([0-9]+)\)/, "\\1", "g", $0);
  sub(/\/\/.*/, "", $0);
  sub(/"nativeID"/, "\"native_id\"", $0);
  sub(/"ID"/, "\"id\"", $0);
  print $0
}

/const struct ppm_event_info g_event_info/ { do_print = 1; }
' < $EVENT_TABLE

echo '}') > src/events/types.rs

rustfmt src/events/types.rs