#!/bin/bash

set -e
set -x

HAS_CARGO_IN_PATH=`which cargo; echo $?`

if [ "${HAS_CARGO_IN_PATH}" -ne "0" ]; then
    source $HOME/.cargo/env
fi

if [ -z "${PODS_TARGET_SRCROOT}" ]; then
    ROOT_DIR="${SRCROOT}/../rust"
else
    ROOT_DIR="${PODS_TARGET_SRCROOT}/rust"
fi

build_path="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin"

#
# Figure out the correct Rust target from the ARCHS and PLATFORM.
# This script expects just one element in ARCHS.
case "$ARCHS" in
	"arm64")	rust_arch="aarch64" ;;
	"x86_64")	rust_arch="x86_64" ;;
	*)			echo "error: unsupported architecture: $ARCHS" ;;
esac
if [[ "$PLATFORM_NAME" == "macosx" ]]; then
	rust_platform="apple-darwin"
else
	rust_platform="apple-ios"
fi
if [[ "$PLATFORM_NAME" == "iphonesimulator" ]]; then
    if [[ "${rust_arch}" == "aarch64" ]]; then
        rust_abi="-sim"
    else
        rust_abi=""
    fi
else
	rust_abi=""
fi
rust_target="${rust_arch}-${rust_platform}${rust_abi}"
#
# Build library in debug or release
build_args=(--manifest-path "${ROOT_DIR}/Cargo.toml" --target "${rust_target}")
if [[ "$CONFIGURATION" == "Release" ]]; then
	rust_config="release"
	env PATH="${build_path}" cargo build --release "${build_args[@]}"
elif [[ "$CONFIGURATION" == "Debug" ]]; then
	rust_config="debug"
	env PATH="${build_path}" cargo build "${build_args[@]}"
else
    echo "error: Unexpected build configuration: $CONFIGURATION"
fi
#

cp -f "${ROOT_DIR}"/target/${rust_target}/${rust_config}/*.a "${CONFIGURATION_BUILD_DIR}"/
cp -f "${ROOT_DIR}"/include/*.h "${CONFIGURATION_BUILD_DIR}"/

exit 0