#!/bin/bash
set -euo pipefail
export LC_ALL=C

usage() {
    echo "Usage: $0 x64|arm64" >&2
    echo "Requires a matching Linux build host, CMake, Ninja, GCC, OpenSSL 3 and zlib development files, and the .NET 10 SDK." >&2
    echo "Optional: BC_DIST, BC_BUILD_JOBS, BC_CACHE_DIR, BC_CURL_ARCHIVE, BC_MANAGED_PUBLISH (prebuilt self-contained publish directory)." >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in
    x64) host_arch=x86_64; elf_machine='Advanced Micro Devices X86-64' ;;
    arm64) host_arch=aarch64; elf_machine=AArch64 ;;
    *) usage ;;
esac
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != "$host_arch" ]; then
    echo "Run this script in a Linux $host_arch environment." >&2
    exit 1
fi

root=$(cd "$(dirname "$0")/../../../.." && pwd)
version=$(sed -n 's/^project(bControl VERSION \([^ ]*\) .*/\1/p' "$root/CMakeLists.txt")
[ -n "$version" ] || { echo "Could not determine the release version." >&2; exit 1; }
dist=${BC_DIST:-$root/dist}
jobs=${BC_BUILD_JOBS:-$(nproc)}
name=ShelfView-$version-linux-$1
curl_version=8.22.0
curl_digest=f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7

work=$(mktemp -d "${TMPDIR:-/tmp}/shelfview-linux.XXXXXX")
candidate=
download=
cleanup() {
    if [ -n "$candidate" ]; then rm -f -- "$candidate"; fi
    if [ -n "$download" ]; then rm -f -- "$download"; fi
    rm -r -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

check_curl() { printf '%s  %s\n' "$curl_digest" "$1" | sha256sum --check; }
cache=${BC_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/bcontrol}/sources
archive=${BC_CURL_ARCHIVE:-$cache/curl-$curl_version.tar.xz}
if [ -z "${BC_CURL_ARCHIVE:-}" ] && ! check_curl "$archive" >/dev/null 2>&1; then
    mkdir -p "$cache"
    download=$(mktemp "$cache/.curl-$curl_version.XXXXXX")
    curl --fail --location --retry 2 --max-time 300 --output "$download" "https://curl.se/download/curl-$curl_version.tar.xz"
    check_curl "$download"
    mv -f -- "$download" "$archive"
    download=
fi
check_curl "$archive"
tar -xJf "$archive" -C "$work"
curl_source=$work/curl-$curl_version
patch -d "$curl_source" -p1 < "$root/third_party/curl/location-1xx.patch"
cmake -S "$curl_source" -B "$work/curl" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$work/deps" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=ON -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF \
    -DBUILD_EXAMPLES=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF \
    -DCURL_USE_OPENSSL=ON -DCURL_USE_PKGCONFIG=OFF -DCURL_ZLIB=ON \
    -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_USE_LIBSSH=OFF -DCURL_USE_GSSAPI=OFF \
    -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON -DUSE_NGHTTP2=OFF -DUSE_LIBIDN2=OFF \
    -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF
cmake --build "$work/curl" --parallel "$jobs"
cmake --install "$work/curl"

cmake -S "$root" -B "$work/native" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON '-DCMAKE_INSTALL_RPATH=$ORIGIN' \
    '-DCMAKE_C_FLAGS=-D_POSIX_C_SOURCE=200809L -Wno-error=misleading-indentation -Wno-error=format-truncation' \
    -DCURL_DIR="$work/deps/lib/cmake/CURL" -DBC_BUILD_AGENT=OFF -DBUILD_TESTING=OFF
cmake --build "$work/native" --parallel "$jobs"

package=$work/$name
mkdir -p "$package/Licenses"
if [ -n "${BC_MANAGED_PUBLISH:-}" ]; then
    cp -a "$BC_MANAGED_PUBLISH/." "$package/"
else
    dotnet publish "$root/frontends/desktop/src/BControl.Desktop/BControl.Desktop.csproj" \
        --artifacts-path "$work/managed" -c Release -r "linux-$1" --self-contained true \
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
        -p:EnableCompressionInSingleFile=true -p:BControlSignBuildOutput=false \
        "-p:BControlNativeDir=$work/no-native-copy" -o "$package"
fi
cp -a "$work/native"/libbcontrol*.so* "$package/"
cp -L "$work/deps/lib/libcurl.so.4" "$package/"
cp "$curl_source/COPYING" "$package/Licenses/curl.txt"
cp "$root/third_party/pack200/LICENSE.txt" "$package/Licenses/Pack200.txt"
cp "$root/third_party/libjpeg-turbo/LICENSE.md" "$package/Licenses/libjpeg-turbo.txt"
cp "$root/third_party/libjpeg-turbo/README.ijg" "$package/Licenses/libjpeg-ijg.txt"
cp "$root/docs/pack200-dependency.txt" "$package/Licenses/Pack200-SOURCE.txt"

[ -x "$package/ShelfView" ] && [ -f "$package/libbcontrol_client.so" ]
for binary in "$package/ShelfView" "$package"/lib*.so "$package/libcurl.so.4"; do
    machine=$(readelf -h "$binary" | sed -n 's/^ *Machine: *//p')
    if [ "$machine" != "$elf_machine" ]; then
        echo "Unexpected ELF architecture for $binary: $machine" >&2
        exit 1
    fi
    dependencies=$(ldd "$binary")
    if [[ "$dependencies" == *'not found'* ]]; then
        printf '%s\n' "$dependencies" >&2
        exit 1
    fi
done

mkdir -p "$dist"
candidate=$(mktemp "$dist/.$name.XXXXXX")
tar -czf "$candidate" -C "$work" "$name"
tar -tzf "$candidate" >/dev/null
chmod 644 "$candidate"
mv -f -- "$candidate" "$dist/$name.tar.gz"
candidate=
echo "Package: $dist/$name.tar.gz"
