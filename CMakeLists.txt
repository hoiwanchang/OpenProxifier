cmake_minimum_required(VERSION 3.20)

# Auto-configure vcpkg if not set
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(EXISTS "D:/GitHub/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "D:/GitHub/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
    endif()
endif()

# Auto-configure Qt6 path if not set
if(NOT DEFINED CMAKE_PREFIX_PATH)
    if(EXISTS "D:/Qt/6.10.1/msvc2022_64")
        set(CMAKE_PREFIX_PATH "D:/Qt/6.10.1/msvc2022_64" CACHE STRING "")
    endif()
endif()

project(MiniProxifier VERSION 1.0.0 LANGUAGES CXX)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows platform check
if(NOT WIN32)
    message(FATAL_ERROR "This project only supports Windows platform")
endif()

# Qt auto tools
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Architecture detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_SUFFIX "x64")
    message(STATUS "Building for 64-bit architecture")
else()
    set(ARCH_SUFFIX "x86")
    message(STATUS "Building for 32-bit architecture")
endif()

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
qt_standard_project_setup()

# Find Microsoft Detours (via vcpkg)
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
get_filename_component(DETOURS_INSTALLED_DIR "${DETOURS_INCLUDE_DIRS}" DIRECTORY)
find_library(
    DETOURS_LIBRARY_RELEASE
    NAMES detours
    PATHS "${DETOURS_INSTALLED_DIR}/lib"
    NO_DEFAULT_PATH
    REQUIRED
)
find_library(
    DETOURS_LIBRARY_DEBUG
    NAMES detours
    PATHS "${DETOURS_INSTALLED_DIR}/debug/lib"
    NO_DEFAULT_PATH
)

set(DETOURS_LIBRARIES optimized ${DETOURS_LIBRARY_RELEASE})
if(DETOURS_LIBRARY_DEBUG)
    list(APPEND DETOURS_LIBRARIES debug ${DETOURS_LIBRARY_DEBUG})
elseif((CMAKE_CONFIGURATION_TYPES AND "Debug" IN_LIST CMAKE_CONFIGURATION_TYPES) OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(WARNING "Debug Detours library not found; Debug builds will link against the Release Detours library")
else()
    message(STATUS "Debug Detours library not found; using Release Detours library for non-Debug configurations")
endif()

message(STATUS "Detours include: ${DETOURS_INCLUDE_DIRS}")
message(STATUS "Detours release library: ${DETOURS_LIBRARY_RELEASE}")
message(STATUS "Detours debug library: ${DETOURS_LIBRARY_DEBUG}")

# Export architecture suffix for subprojects
set(ARCH_SUFFIX ${ARCH_SUFFIX} CACHE STRING "Architecture suffix" FORCE)

# Add subprojects (DLL injection mode - legacy)
add_subdirectory(common)
add_subdirectory(hookdll)
add_subdirectory(launcher)
add_subdirectory(proxytestapp)

# Add WinDivert-based core engine and CLI (new architecture)
add_subdirectory(core)
add_subdirectory(cli)

# Ensure hookdll is built before launcher
add_dependencies(MiniProxifier MiniProxifierHook)
