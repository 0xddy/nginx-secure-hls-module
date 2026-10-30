#!/usr/bin/env bash
# Incremental validation only: reuse configurations from a previous matrix run.
# Use matrix.sh for first builds or after changing configure options/toolchains.
set -euo pipefail
cd "$(dirname "$0")/.."
work=${HLS_BUILD_ROOT:-/work}
labels=()
for label in nginx-1.24.0-dynamic-no nginx-1.24.0-static-no \
             nginx-1.30.6-dynamic-no nginx-1.30.6-static-no \
             openresty-1.25.3.2-dynamic-no openresty-1.25.3.2-static-no \
             openresty-1.31.8.1-dynamic-no openresty-1.31.8.1-static-no \
             nginx-1.30.6-static-yes; do
    target="$work/$label"
    product_version=${label%-*}; product_version=${product_version%-*}
    source="$target/$product_version"
    test -f "$source/Makefile"
    if ! make -C "$source" -j"${HLS_BUILD_JOBS:-4}" > "$target/make.log" 2>&1; then
        tail -80 "$target/make.log"; exit 1
    fi
    make -C "$source" install > "$target/install.log" 2>&1
    module=$(cat "$target/module.path")
    if [ -n "$module" ]; then
        built=$(find "$source" -path '*/objs/ngx_http_secure_hls_module.so' -print -quit)
        cp "$built" "$module"
    fi
    if [[ "$label" == *-yes ]]; then
        export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1
        export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:suppressions=$PWD/tests/ubsan.supp"
    fi
    echo "Checking $label"
    python3 tests/integration.py --nginx "$(cat "$target/binary.path")" --module "$module" --work "$target/test"
    if [ -n "${HLS_ARTIFACT_ROOT:-}" ]; then
        dest="$HLS_ARTIFACT_ROOT/$label"
        mkdir -p "$dest"
        cp "$(cat "$target/binary.path")" "$dest/nginx"
        if [ -n "$module" ]; then cp "$module" "$dest/"; fi
        cp -r "$target/test" "$dest/"
        cp "$target/configure.log" "$target/make.log" "$dest/"
    fi
    labels+=("$label")
done
python3 scripts/report.py --work "$work" \
    --output "${HLS_ARTIFACT_ROOT:-$work}/verification.json" "${labels[@]}"
