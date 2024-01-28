cmake_minimum_required(VERSION 3.13)
set(CMAKE_VERBOSE_MAKEFILE on)

add_compile_options(
        -fexceptions
        -frtti
        -std=c++17)

file(GLOB native_module_SRC CONFIGURE_DEPENDS *.cpp)
add_library(native_module STATIC ${native_module_SRC})

find_package(ReactAndroid REQUIRED CONFIG)
target_include_directories(native_module PUBLIC .)
#target_include_directories(react_codegen_RNCslMobileBridgeSpec PUBLIC .)

target_link_libraries(native_module
        ReactAndroid::jsi
        react_nativemodule_core)
