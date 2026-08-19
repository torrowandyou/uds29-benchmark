#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")" && pwd)
source_dir=${TONGSUO_SOURCE:-"$root_dir/../Tongsuo"}
build_dir=${TONGSUO_BUILD:-"$root_dir/build/tongsuo-build"}
install_dir=${TONGSUO_PREFIX:-"$root_dir/build/tongsuo-install"}
jobs=${JOBS:-2}

mkdir -p "$build_dir" "$install_dir"
cd "$build_dir"
if [[ ! -f Makefile ]]; then
  "$source_dir/Configure" --prefix="$install_dir" --openssldir="$install_dir/ssl" \
    no-tests
fi
make -j"$jobs"
make install_sw
printf 'Tongsuo installed in %s\n' "$install_dir"
