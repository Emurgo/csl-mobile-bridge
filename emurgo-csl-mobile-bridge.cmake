cmake_minimum_required(VERSION 3.13)

#set(CMAKE_VERBOSE_MAKEFILE ON)
#set(CMAKE_CXX_STANDARD 17)

set (BUILD_DIR ${CMAKE_CURRENT_LIST_DIR}/android/build)
set(LIB_ANDROID_GENERATED_JNI_DIR ${CMAKE_CURRENT_LIST_DIR}/android/build/generated/source/codegen/jni)

if (NOT DEFINED REACT_ANDROID_DIR)
    set(REACT_ANDROID_DIR ${CMAKE_CURRENT_LIST_DIR}/node_modules/react-native/android)
endif()

if (NOT DEFINED NODE_MODULES_DIR)
    set(NODE_MODULES_DIR ${CMAKE_CURRENT_LIST_DIR}/node_modules)
endif()

file(GLOB native_module_SRC CONFIGURE_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/cpp/*.cpp)

if (NOT EXISTS  ${NODE_MODULES_DIR}/react-native )
    message(FATAL_ERROR "Can't find \" ${NODE_MODULES_DIR}/react-native\". Please run npm install in the root of your project directory")
endif()

add_library(cls_mobile_bridge_jsi SHARED ${native_module_SRC} )

target_include_directories(
        cls_mobile_bridge_jsi
        PRIVATE
        "${NODE_MODULES_DIR}/react-native/React"
        "${NODE_MODULES_DIR}/react-native/React/Base"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
        "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
)

include_directories(
        "${CMAKE_CURRENT_LIST_DIR}/cpp/"
        "${CMAKE_CURRENT_LIST_DIR}/android/build/generated/source/codegen/jni/."
        "${CMAKE_CURRENT_LIST_DIR}/android/build/generated/source/codegen/jni/react/renderer/components/RNCslMobileBridgeSpec"
)

add_library(react_native_haskell_shelley  SHARED IMPORTED )
target_include_directories(react_native_haskell_shelley INTERFACE "${CMAKE_CURRENT_LIST_DIR}/rust/include")
set_target_properties(react_native_haskell_shelley PROPERTIES IMPORTED_LOCATION ${BUILD_DIR}/rustJniLibs/android/${ANDROID_ABI}/libreact_native_haskell_shelley.so )

target_link_libraries(
        cls_mobile_bridge_jsi
        react_codegen_RNCslMobileBridgeSpec
        react_native_haskell_shelley
         jsi
)
