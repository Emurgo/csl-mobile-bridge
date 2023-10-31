#!/bin/bash

set -e
set -x

if [ -z "${PODS_TARGET_SRCROOT}" ]; then
    ROOT_DIR="${SRCROOT}/../rust"
else
    ROOT_DIR="${PODS_TARGET_SRCROOT}/rust"
fi

#
# Figure out the correct Rust target from the ARCHS and PLATFORM.
# This script expects just one element in ARCHS.
#collect all lib paths into array
LIB_LIST=()
ARCH_LIST=$(echo $ARCHS | tr ";" "\n")
for CURRENT_ARCH in $ARCH_LIST; do
    case "$CURRENT_ARCH" in
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
      cmd="cargo build --release ${build_args[@]}"
      bash -l -c "${cmd}"
    elif [[ "$CONFIGURATION" == "Debug" ]]; then
    	rust_config="debug"
      cmd="cargo build ${build_args[@]}"
      bash -l -c "${cmd}"
    else
        echo "error: Unexpected build configuration: $CONFIGURATION"
    fi
    LIB_LIST+=("${ROOT_DIR}"/target/"${rust_target}"/"${rust_config}"/*.a)
done
#


if [ ${#LIB_LIST[@]} -gt 1 ]; then
    TMP_DIR="${ROOT_DIR}"/target/tmp
    LIB_NAME=$(basename "${LIB_LIST[0]}")
    mkdir -p "${TMP_DIR}"
    lipo -create "${LIB_LIST[@]}" -output "${TMP_DIR}/${LIB_NAME}"
    cp -f "${TMP_DIR}/${LIB_NAME}" "${CONFIGURATION_BUILD_DIR}"/
    rm -rf "${TMP_DIR}"
else
    cp -f "${LIB_LIST[0]}" "${CONFIGURATION_BUILD_DIR}"/
fi

cp -f "${ROOT_DIR}"/include/*.h "${CONFIGURATION_BUILD_DIR}"/

exit 0