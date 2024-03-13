#!/usr/bin/env bash

cd "$(dirname "$0")/.." || exit 1

EVENT_TABLE="api/event_table.c"

(cat << EOF
use falco_event_derive::event_info;

event_info! {
EOF

grep -F '[PPME' $EVENT_TABLE | sed '-res@DIRFD_PARAM\(([0-9]+)\)@\1@g' '-res@//.*@@' | awk '
/GENERIC/ {
  sub(/nativeID/, "native_id", $0);
  sub(/ID/, "id", $0);
}

{
  print $0
}
'

echo '}') > src/events/types.rs