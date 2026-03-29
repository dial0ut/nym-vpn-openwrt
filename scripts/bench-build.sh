#!/bin/bash
# Benchmark build memory usage via docker stats.
# Samples every second, reports peak and average memory.
#
# Usage: ./scripts/bench-build.sh [build-musl.sh args...]
# Example: ./scripts/bench-build.sh --dynamic mips

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Build Memory Benchmark ==="
echo "Args: $*"
echo ""

# Run build-musl.sh with -t only (no -i) by setting DOCKER_FLAGS
# Override the docker run flags to avoid TTY issues in background
export BENCH_MODE=1

# Start the build in background (redirect to fd 3 so we still see output)
bash "$PROJECT_ROOT/scripts/build-musl.sh" "$@" &
BUILD_PID=$!

# Wait for docker container to start
sleep 5

sample_count=0
total_mb=0
peak_mb=0

while kill -0 "$BUILD_PID" 2>/dev/null; do
    # Get memory from all running containers (there should be just one during build)
    mem_bytes=$(docker stats --no-stream --format '{{.MemUsage}}' 2>/dev/null \
        | head -1 \
        | grep -oE '^[0-9.]+(MiB|GiB)' \
        || echo "0MiB")

    # Parse to MB
    value=$(echo "$mem_bytes" | grep -oE '^[0-9.]+')
    unit=$(echo "$mem_bytes" | grep -oE '(MiB|GiB)')

    mem_mb=0
    if [ "$unit" = "GiB" ]; then
        mem_mb=$(echo "$value * 1024" | bc 2>/dev/null | cut -d. -f1)
    elif [ "$unit" = "MiB" ]; then
        mem_mb=$(echo "$value" | cut -d. -f1)
    fi

    if [ "${mem_mb:-0}" -gt 0 ] 2>/dev/null; then
        sample_count=$((sample_count + 1))
        total_mb=$((total_mb + mem_mb))
        if [ "$mem_mb" -gt "$peak_mb" ]; then
            peak_mb=$mem_mb
        fi
        # Print a dot every 30 samples so you know it's working
        if [ $((sample_count % 30)) -eq 0 ]; then
            echo "[bench] ${sample_count}s — current: ${mem_mb}MB, peak: ${peak_mb}MB"
        fi
    fi

    sleep 1
done

wait "$BUILD_PID"
exit_code=$?

echo ""
echo "=== Memory Benchmark Results ==="
if [ "$sample_count" -gt 0 ]; then
    avg_mb=$((total_mb / sample_count))
    echo "Samples:  ${sample_count}s"
    echo "Peak:     ${peak_mb} MB"
    echo "Average:  ${avg_mb} MB"
else
    echo "No memory samples collected (was the docker container running?)"
fi
echo "Exit code: $exit_code"
exit "$exit_code"
