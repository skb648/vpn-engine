# ══════════════════════════════════════════════════════════════════════════════
# CMakeLists.txt — ZeroTier P2P Mesh VPN Engine Build Configuration
#
# This CMake script builds the native library that bridges Android's TUN
# interface with the ZeroTier virtual network. It links against the
# pre-built ZeroTier SDK (libzt) which provides the P2P mesh networking.
#
# Directory structure expected:
#   cpp/
#   ├── CMakeLists.txt          (this file)
#   ├── native-lib.cpp          (JNI bridge)
#   ├── ZeroTierEngine.cpp      (ZT engine + TUN bridge)
#   ├── zt_stubs.cpp            (stub implementations when libzt is missing)
#   ├── include/
#   │   ├── ZeroTierEngine.h    (engine header)
#   │   └── ZeroTierSockets.h   (libzt C API header — from SDK)
#   └── libs/
#       ├── arm64-v8a/
#       │   └── libzt.so         (pre-built ZeroTier SDK for arm64)
#       ├── armeabi-v7a/
#       │   └── libzt.so
#       ├── x86/
#       │   └── libzt.so
#       └── x86_64/
#           └── libzt.so
# ══════════════════════════════════════════════════════════════════════════════

cmake_minimum_required(VERSION 3.22.1)

project(vpn-engine)

# ── C++ Standard ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ══════════════════════════════════════════════════════════════════════════════
# ZeroTier SDK Integration
# ══════════════════════════════════════════════════════════════════════════════

# CRITICAL FIX: Look for libzt.so in jniLibs/ (tracked in Git) NOT cpp/libs/
# The cpp/libs/ directory is NOT in Git, so CI builds always fell back to stubs.
# jniLibs/ is tracked and Android packages from there anyway.
set(ZT_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}")

# ── Try to find pre-built ZeroTier library ────────────────────────────────────

# Prefer shared library (libzt.so) — smaller final binary with only one copy
set(ZT_STATIC_LIB "${ZT_LIB_DIR}/libzt.a")
set(ZT_SHARED_LIB "${ZT_LIB_DIR}/libzt.so")

# Source files — stubs are included only when real SDK is NOT found
set(ENGINE_SOURCES
    native-lib.cpp
    ZeroTierEngine.cpp
    Socks5Server.cpp
)

if(EXISTS "${ZT_SHARED_LIB}")
    message(STATUS "ZeroTier: Found shared library at ${ZT_SHARED_LIB}")

    add_library(zt SHARED IMPORTED)
    set_target_properties(zt PROPERTIES
        IMPORTED_LOCATION "${ZT_SHARED_LIB}"
    )

    set(ZT_LINK_LIBS zt)
    # When real SDK is present, DO NOT include stubs (they use weak symbols
    # but it's cleaner to exclude them entirely)
    message(STATUS "ZeroTier: Real SDK found — stubs will be EXCLUDED")
    message(STATUS "ZeroTier: libzt.so will be linked as shared library dependency")
    message(STATUS "ZeroTier: Ensure System.loadLibrary(\"zt\") is called before System.loadLibrary(\"vpn-engine\") in ZtEngine.kt")

elseif(EXISTS "${ZT_STATIC_LIB}")
    message(STATUS "ZeroTier: Found static library at ${ZT_STATIC_LIB}")

    add_library(zt STATIC IMPORTED)
    set_target_properties(zt PROPERTIES
        IMPORTED_LOCATION "${ZT_STATIC_LIB}"
    )

    # Static linking needs all transitive dependencies
    set(ZT_LINK_LIBS zt)
    message(STATUS "ZeroTier: Real SDK found — stubs will be EXCLUDED")

else()
    message(WARNING "ZeroTier SDK library not found at ${ZT_LIB_DIR}/")
    message(WARNING "The VPN engine will compile but fail at runtime.")
    message(WARNING "To fix: Download libzt from https://github.com/zerotier/libzt")
    message(WARNING "Place libzt.so in: ${ZT_LIB_DIR}/")

    # Include stubs when real SDK is not available
    list(APPEND ENGINE_SOURCES zt_stubs.cpp)
    set(ZT_LINK_LIBS "")
    message(STATUS "ZeroTier: Stubs will be INCLUDED (no real SDK)")
endif()

# ── Build our native library ──────────────────────────────────────────────────
add_library(
    vpn-engine
    SHARED
    ${ENGINE_SOURCES}
)

# ── Include directories ──────────────────────────────────────────────────────
target_include_directories(
    vpn-engine
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ── Find and link NDK libraries ───────────────────────────────────────────────
find_library(android-lib android)
find_library(log-lib log)

target_link_libraries(
    vpn-engine
    ${ZT_LINK_LIBS}
    ${android-lib}
    ${log-lib}
)

# ── Compiler flags ────────────────────────────────────────────────────────────
target_compile_options(
    vpn-engine
    PRIVATE
    -Wall
    -Wextra
    -Werror=return-type
    -Werror=uninitialized
    -O2
    -fstack-protector-strong
)

# ── Preprocessor definitions ─────────────────────────────────────────────────
add_definitions(-DANDROID_STL=c++_shared)
