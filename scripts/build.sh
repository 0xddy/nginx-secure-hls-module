#!/usr/bin/env bash
set -euo pipefail
product=${1:-nginx}
version=${2:-1.30.6}
mode=${3:-dynamic}
san=${4:-no}
case "$product" in nginx|openresty) ;; *) exit 2;; esac
case "$mode" in static|dynamic) ;; *) exit 2;; esac
src=$(cd "$(dirname "$0")/.." && pwd)
work=${HLS_BUILD_ROOT:-/work}
label="$product-$version-$mode-$san"
target="$work/$label"
mkdir -p "$target" "$work/cache"
archive="$product-$version.tar.gz"
if [ -f "$src/.cache/$archive" ]; then
    cp "$src/.cache/$archive" "$work/cache/$archive"
fi
if [ ! -f "$work/cache/$archive" ]; then
    case "$product" in
        nginx) url="https://nginx.org/download/$archive" ;;
        openresty) url="https://openresty.org/download/$archive" ;;
    esac
    curl --fail --location --retry 2 "$url" -o "$work/cache/$archive"
fi
expected=$(awk -v file="$archive" '$2 == file {print $1}' "$src/scripts/sources.sha256")
if [ -n "$expected" ]; then
    printf '%s  %s\n' "$expected" "$work/cache/$archive" | sha256sum --check --status
fi
tar xzf "$work/cache/$archive" -C "$target"
cd "$target/$product-$version"
options=(--prefix="$target/install" --with-http_ssl_module --with-http_realip_module --with-debug)
if [ "$mode" = dynamic ]; then
    options+=(--with-compat --add-dynamic-module="$src")
else
    options+=(--add-module="$src")
fi
if [ "$san" = yes ]; then
    options+=(--with-cc-opt='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined' --with-ld-opt='-fsanitize=address,undefined')
fi
if ! ./configure "${options[@]}" > "$target/configure.log" 2>&1; then
    tail -80 "$target/configure.log"; exit 1
fi
if ! make -j"${HLS_BUILD_JOBS:-4}" > "$target/make.log" 2>&1; then
    tail -100 "$target/make.log"; exit 1
fi
make install > "$target/install.log" 2>&1
if [ "$product" = openresty ]; then
    binary="$target/install/nginx/sbin/nginx"
    objs="$(find build -type d -path '*/nginx-*/objs' | head -1)"
else
    binary="$target/install/sbin/nginx"
    objs=objs
fi
module=''
if [ "$mode" = dynamic ]; then
    module="$target/ngx_http_secure_hls_module.so"
    cp "$objs/ngx_http_secure_hls_module.so" "$module"
fi
printf '%s\n' "$binary" > "$target/binary.path"
printf '%s\n' "$module" > "$target/module.path"
printf 'Built %s\n' "$label"
