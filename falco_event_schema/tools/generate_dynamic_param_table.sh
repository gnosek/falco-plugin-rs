#!/usr/bin/env bash

cd "$(dirname "$0")/.." || exit 1

DYNAMIC_PARAM_TABLE="api/dynamic_params_table.c"

(cat << EOF
use falco_schema_derive::dynamic_params;

dynamic_params! {
EOF

sed -n '/ppm_param_info/,$p' < $DYNAMIC_PARAM_TABLE

echo '}') > src/fields/dynamic_params.rs

rustfmt src/fields/dynamic_params.rs
