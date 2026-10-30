#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
work=${HLS_BUILD_ROOT:-/work}
labels=()
export_result() {
    if [ -n "${HLS_ARTIFACT_ROOT:-}" ]; then
        dest="$HLS_ARTIFACT_ROOT/$(basename "$target")"
        mkdir -p "$dest"
        cp "$(cat "$target/binary.path")" "$dest/nginx"
        if [ -s "$target/module.path" ]; then
            module=$(cat "$target/module.path")
            if [ -n "$module" ]; then cp "$module" "$dest/"; fi
        fi
        cp -r "$target/test" "$dest/"
        cp "$target/configure.log" "$target/make.log" "$dest/"
    fi
}
for pair in ${HLS_MATRIX:-nginx:1.24.0 nginx:1.30.6 openresty:1.25.3.2 openresty:1.31.8.1}; do
    for mode in dynamic static; do
        product=${pair%:*}; version=${pair#*:}
        bash scripts/build.sh "$product" "$version" "$mode"
        target="$work/$product-$version-$mode-no"
        python3 tests/integration.py --nginx "$(cat "$target/binary.path")" --module "$(cat "$target/module.path")" --work "$target/test"
        export_result
        labels+=("$(basename "$target")")
    done
done
bash scripts/build.sh nginx 1.30.6 static yes
target="$work/nginx-1.30.6-static-yes"
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:suppressions=$PWD/tests/ubsan.supp" \
    python3 tests/integration.py --nginx "$(cat "$target/binary.path")" --work "$target/test"
export_result
labels+=("$(basename "$target")")
python3 scripts/report.py --work "$work" \
    --output "${HLS_ARTIFACT_ROOT:-$work}/verification.json" "${labels[@]}"
