cmake_minimum_required(VERSION 3.13)
set(CMAKE_VERBOSE_MAKEFILE on)

#don't rename it, react-native depends on it
project(appmodules)


add_compile_options(
        -fexceptions
        -frtti
        -std=c++17)

if (NOT DEFINED NODE_MODULES_DIR)
    set(NODE_MODULES_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../../node_modules)
endif()

if (NOT EXISTS  ${NODE_MODULES_DIR}/react-native )
    message(FATAL_ERROR "Can't find \" ${NODE_MODULES_DIR}/react-native\". Please run npm install in the root of your project directory")
endif()

set(CPP_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../../../cpp)
file(GLOB cxx_modules_loader_SRC CONFIGURE_DEPENDS ${CPP_DIR}/*.cpp)
add_library(cxx_modules_loader STATIC ${cxx_modules_loader_SRC})

include_directories(${CPP_DIR})

include(${REACT_ANDROID_DIR}/cmake-utils/ReactNative-application.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../../../../../../emurgo-csl-mobile-bridge.cmake)

target_link_libraries(cxx_modules_loader
        jsi
        cls_mobile_bridge_jsi)

target_link_libraries(${CMAKE_PROJECT_NAME} cxx_modules_loader)
