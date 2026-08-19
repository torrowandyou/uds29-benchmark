#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "$0")" && pwd)

sanitize_device_id() {
  LC_ALL=C tr '[:upper:]' '[:lower:]' |
    sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//'
}

local_user=$(id -un 2>/dev/null || printf unknown-user)
local_host=$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf unknown-host)
platform_os=$(uname -s 2>/dev/null || printf unknown-os)
platform_arch=$(uname -m 2>/dev/null || printf unknown-arch)
raw_device_id=$(printf '%s-%s-%s-%s' "$local_user" "$local_host" "$platform_os" "$platform_arch")
auto_device_id=$(printf '%s' "$raw_device_id" | sanitize_device_id)
device_id=${DEVICE_ID:-$auto_device_id}

if [[ "${1:-}" == "--print-device-id" && $# -eq 1 ]]; then
  printf '%s\n' "$device_id"
  exit 0
fi
if [[ $# -ne 0 ]]; then
  echo "Usage: $0" >&2
  echo "Configuration uses environment variables such as DEVICE_ID, ITERATIONS, and BENCH_CPU." >&2
  exit 2
fi

iterations=${ITERATIONS:-10000}
warmup=${WARMUP:-1000}
if [[ ! "$device_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "Invalid DEVICE_ID: $device_id" >&2
  echo "Use only letters, digits, dot, underscore, and hyphen." >&2
  exit 2
fi
if [[ ! "$iterations" =~ ^[1-9][0-9]*$ ]] || [[ ! "$warmup" =~ ^[0-9]+$ ]]; then
  echo "ITERATIONS must be positive and WARMUP must be a non-negative integer." >&2
  exit 2
fi

results_root=${RESULTS_ROOT:-"$root_dir/results"}
figures_root=${FIGURES_ROOT:-"$root_dir/figures"}
result_dir="$results_root/$device_id"
figure_dir="$figures_root/$device_id"
binary="$root_dir/build/uds29_bench"
tongsuo_prefix=${TONGSUO_PREFIX:-"$root_dir/build/tongsuo-install"}
tongsuo_source=${TONGSUO_SOURCE:-"$root_dir/../Tongsuo"}
compiler=${CC:-cc}

crypto_library=
for library_dir in "$tongsuo_prefix/lib64" "$tongsuo_prefix/lib"; do
  for candidate in "$library_dir"/libcrypto.*; do
    if [[ -f "$candidate" ]]; then
      crypto_library=$candidate
      break 2
    fi
  done
done

if [[ ! -f "$tongsuo_prefix/include/openssl/crypto.h" || -z "$crypto_library" ]]; then
  if [[ ! -x "$tongsuo_source/Configure" ]]; then
    echo "Tongsuo source not found at: $tongsuo_source" >&2
    echo "Place it next to this repository or set TONGSUO_SOURCE." >&2
    exit 2
  fi
  jobs=${JOBS:-}
  if [[ -z "$jobs" ]]; then
    jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || printf 2)
  fi
  printf 'Building local Tongsuo with %s jobs...\n' "$jobs"
  env TONGSUO_SOURCE="$tongsuo_source" TONGSUO_PREFIX="$tongsuo_prefix" JOBS="$jobs" "$root_dir/build_tongsuo.sh"
fi

make -C "$root_dir" TONGSUO_PREFIX="$tongsuo_prefix" CC="$compiler" all
mkdir -p "$result_dir" "$figure_dir"

benchmark=("$binary" --iterations "$iterations" --warmup "$warmup" --csv "$result_dir/results.csv")
cpu_label=unbound
if [[ -n "${BENCH_CPU:-}" ]]; then
  if ! command -v taskset >/dev/null 2>&1; then
    echo "BENCH_CPU was set, but taskset is not available." >&2
    exit 2
  fi
  benchmark=(taskset -c "$BENCH_CPU" "${benchmark[@]}")
  cpu_label=$BENCH_CPU
fi

library_path="$tongsuo_prefix/lib64:$tongsuo_prefix/lib"
if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
  library_path="$library_path:$LD_LIBRARY_PATH"
fi
dyld_library_path="$tongsuo_prefix/lib64:$tongsuo_prefix/lib"
if [[ -n "${DYLD_LIBRARY_PATH:-}" ]]; then
  dyld_library_path="$dyld_library_path:$DYLD_LIBRARY_PATH"
fi

metadata_command=(
  python3 "$root_dir/scripts/collect_metadata.py"
  --output "$result_dir/metadata.json"
  --device-id "$device_id"
  --repo-root "$root_dir"
  --binary "$binary"
  --tongsuo-prefix "$tongsuo_prefix"
  --tongsuo-source "$tongsuo_source"
  --compiler "$compiler"
  --iterations "$iterations"
  --warmup "$warmup"
  --cpu-affinity "$cpu_label"
)
env LD_LIBRARY_PATH="$library_path" DYLD_LIBRARY_PATH="$dyld_library_path" "${metadata_command[@]}"
printf 'Device: %s\n' "$device_id"
printf 'Running benchmark (%s iterations, %s warmup)...\n' "$iterations" "$warmup"
env LD_LIBRARY_PATH="$library_path" DYLD_LIBRARY_PATH="$dyld_library_path" "${benchmark[@]}" 2>&1 | tee "$result_dir/results.txt"

python3 "$root_dir/scripts/make_paper_figures.py" "$result_dir/results.csv" "$figure_dir/latency_by_phase.svg" --figure latency
python3 "$root_dir/scripts/make_paper_figures.py" "$result_dir/results.csv" "$figure_dir/payload_size.svg" --figure payload
python3 "$root_dir/scripts/make_paper_figures.py" "$result_dir/results.csv" "$figure_dir/latency_payload_tradeoff.svg" --figure tradeoff
python3 "$root_dir/scripts/make_paper_figures.py" "$result_dir/results.csv" "$figure_dir/isotp_frames.svg" --figure isotp

printf 'Results: %s\nFigures: %s\n' "$result_dir" "$figure_dir"
