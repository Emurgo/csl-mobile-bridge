#!/bin/bash

set -e

HAS_CARGO_IN_PATH=`which cargo; echo $?`
MAC_OS_VERSION=`sw_vers -productVersion | cut -d '.' -f 1`
MAC_CURRENT_ARCH=`uname -m`

if [ "${HAS_CARGO_IN_PATH}" -ne "0" ]; then
    source $HOME/.cargo/env
fi

if [[ -n "${DEVELOPER_SDK_DIR:-}" ]] && [[ "$MAC_OS_VERSION" != "11" ]]; then
  # Assume we're in Xcode, which means we're probably cross-compiling.
  # In this case, we need to add an extra library search path for build scripts and proc-macros,
  # which run on the host instead of the target.
  # (macOS Big Sur does not have linkable libraries in /usr/lib/.)
  export LIBRARY_PATH="${DEVELOPER_SDK_DIR}/MacOSX.sdk/usr/lib:${LIBRARY_PATH:-}"
fi

if [ -z "${PODS_TARGET_SRCROOT}" ]; then
    ROOT_DIR="${SRCROOT}/../rust"
else
    ROOT_DIR="${PODS_TARGET_SRCROOT}/rust"
fi

CONFIG_PATH=$(echo $CONFIGURATION | sed 's/^[^.]*\.//')
OUTPUT_DIR=`echo "${CONFIG_PATH}" | tr '[:upper:]' '[:lower:]'`
LIPO_BIN_TARGET_DIR="universal"

cd "${ROOT_DIR}"

if [[ "$TARGET_DEVICE_PLATFORM_NAME" == "iphonesimulator" ]]  && [[ "$MAC_CURRENT_ARCH" == "arm64" ]]; then
  # If we're building for the arm simulator on an M1 Mac, we need to use the x86_64-apple-ios-sim target.
  # Otherwise, lipo will compile for arm64 iphone that can't run on the simulator.
  cargo lipo --targets="aarch64-apple-ios-sim"
  LIPO_BIN_TARGET_DIR="aarch64-apple-ios-sim"
else
  cargo lipo --xcode-integ
fi

mkdir -p "${CONFIGURATION_BUILD_DIR}"

cp -f "${ROOT_DIR}"/target/"${LIPO_BIN_TARGET_DIR}"/"${OUTPUT_DIR}"/*.a "${CONFIGURATION_BUILD_DIR}"/
cp -f "${ROOT_DIR}"/include/*.h "${CONFIGURATION_BUILD_DIR}"/

exit 0
