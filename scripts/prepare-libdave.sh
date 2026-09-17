#!/usr/bin/env bash
set -euo pipefail

platform=${1:-linux}
destination=${2:-.native/libdave/$platform}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
revision=9686fbaea864aa19f0675e486672b6a77811b6a1
patch_hash=$(sha256sum "$script_dir/libdave-channel-binding.patch" | cut -d ' ' -f 1)
key="$revision-$patch_hash"
mkdir -p "$destination"
destination=$(cd "$destination" && pwd)
marker="$destination/build-revision.txt"
if [[ -f "$marker" && "$(cat "$marker")" == "$key" && -f "$destination/lib/pkgconfig/dave.pc" ]]; then
  printf 'libdave ready: %s\n' "$destination"
  exit 0
fi
if [[ "$platform" != linux || "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  printf 'Build the patched Windows library with prepare-libdave.ps1 on Windows and copy its installation directory to %s.\n' "$destination" >&2
  exit 1
fi

work="$(dirname "$destination")/.build-linux-${patch_hash:0:12}"
source_dir="$work/source"
mkdir -p "$work" "$(dirname "$destination")/.cache"
if [[ ! -d "$source_dir" ]]; then
  git -c core.autocrlf=false clone --branch v1.2.0/cpp --depth 1 --recurse-submodules https://github.com/discord/libdave.git "$source_dir"
fi
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$revision" ]]
[[ "$(git -C "$source_dir/cpp/vcpkg" rev-parse HEAD)" == 16c71a39e5a0fc0bdb3fad03beef8f38ee00ee3b ]]
if ! git -C "$source_dir" apply --reverse --check "$script_dir/libdave-channel-binding.patch" 2>/dev/null; then
  git -C "$source_dir" apply "$script_dir/libdave-channel-binding.patch"
fi
export VCPKG_DISABLE_METRICS=1
export VCPKG_DOWNLOADS="$work/downloads"
export VCPKG_BINARY_SOURCES="clear;files,$(dirname "$destination")/.cache,readwrite"
export CMAKE_BUILD_PARALLEL_LEVEL=${CMAKE_BUILD_PARALLEL_LEVEL:-4}
export VCPKG_MAX_CONCURRENCY=${VCPKG_MAX_CONCURRENCY:-$CMAKE_BUILD_PARALLEL_LEVEL}
mkdir -p "$VCPKG_DOWNLOADS"
bash "$source_dir/cpp/vcpkg/bootstrap-vcpkg.sh" -disableMetrics
cmake -S "$source_dir/cpp" -B "$work/build" \
  -DCMAKE_BUILD_TYPE=Release -DVCPKG_TARGET_TRIPLET=x64-linux \
  -DVCPKG_MANIFEST_DIR="$source_dir/cpp/vcpkg-alts/boringssl" \
  -DCMAKE_TOOLCHAIN_FILE="$source_dir/cpp/vcpkg/scripts/buildsystems/vcpkg.cmake" \
  -DBUILD_SHARED_LIBS=ON -DREQUIRE_BORINGSSL=ON -DTESTING=OFF \
  -DINSTALL_VCPKG_LICENSES=ON -DCMAKE_INSTALL_PREFIX="$destination"
cmake --build "$work/build" --config Release --target libdave
cmake --install "$work/build" --config Release
mkdir -p "$destination/lib/pkgconfig"
cat > "$destination/lib/pkgconfig/dave.pc" <<'PC'
prefix=${pcfiledir}/../..
libdir=${prefix}/lib
includedir=${prefix}/include

Name: dave
Description: Discord media encryption with Welcome channel binding
Version: 1.2.0-channel-binding.1
Libs: -L${libdir} -ldave
Cflags: -I${includedir}
PC
printf '%s\n' "$key" > "$marker"
printf 'libdave ready: %s\n' "$destination"
