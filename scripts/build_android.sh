#!/usr/bin/env bash
# Build the optimized Android client and package only verified native assets.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:-all}"
case "$mode" in
  all|--native-only|--package-only) ;;
  *) echo 'Usage: scripts/build_android.sh [--native-only|--package-only]' >&2; exit 2 ;;
esac
cd "$root"
command -v pwsh >/dev/null
native_target="${CSQTT_ANDROID_TARGET_DIR:-$root/build/native-client}"
mkdir -p "$native_target"
native_target="$(cd "$native_target" && pwd)"
jobs="${CSQTT_BUILD_JOBS:-3}"
[[ "$jobs" =~ ^[1-9][0-9]?$ ]] || { echo 'CSQTT_BUILD_JOBS must be 1..99' >&2; exit 2; }

if [[ "$mode" != --package-only ]]; then
  : "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to the installed Android NDK}"
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  (
    cd rust-client
    export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384"
    export CMAKE_BUILD_PARALLEL_LEVEL="$jobs"
    cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P 26 build \
      --release --locked --jobs "$jobs" --target-dir "$native_target"
  )
  while read -r abi target; do
    mkdir -p "app/src/main/jniLibs/$abi"
    install -m 0755 "$native_target/$target/release/client" "app/src/main/jniLibs/$abi/libclient.so"
  done <<'ABIS'
arm64-v8a aarch64-linux-android
armeabi-v7a armv7-linux-androideabi
x86_64 x86_64-linux-android
ABIS
  pwsh -NoProfile -File scripts/native_client_provenance.ps1 -Mode Write \
    -CargoTargetDir "$native_target" -Producer scripts/build_android.sh
fi
pwsh -NoProfile -File scripts/native_client_provenance.ps1 -Mode Verify -CargoTargetDir "$native_target"
[[ "$mode" != --native-only ]] || exit 0

if [[ "$mode" != --package-only ]]; then
  CARGO_BUILD_JOBS="$jobs" bash rust-server/build_linux.sh --no-tests
fi
pwsh -NoProfile -File scripts/server_asset_provenance.ps1 -Mode Verify
# Release signing must be explicitly configured. Gradle refuses missing keys.
bash gradlew :app:testDebugUnitTest :app:assembleRelease --no-daemon --console=plain
version="$(sed -n 's/^[[:space:]]*versionName = "\([^"]*\)"/\1/p' app/build.gradle.kts)"
[[ -n "$version" ]] || { echo 'Missing Android versionName' >&2; exit 1; }
mkdir -p app/release
for abi in universal arm64-v8a armeabi-v7a x86_64; do
  install -m 0644 "app/build/outputs/apk/release/app-$abi-release.apk" \
    "app/release/CSQTT-Compatible-$version-$abi.apk"
done
echo "Signed APKs: $root/app/release"
