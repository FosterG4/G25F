cmake_minimum_required(VERSION 3.20)
project(G25F_Injector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Always build with enhanced features for public release
set(BUILD_ENHANCED ON)

# Configure libmem from local lib folder
set(LIBMEM_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(LIBMEM_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)

# Create libmem imported target
add_library(libmem::libmem STATIC IMPORTED)

# Set different library paths for debug and release
set_target_properties(libmem::libmem PROPERTIES
    IMPORTED_LOCATION_DEBUG ${LIBMEM_LIB_DIR}/debug/libmem.lib
    IMPORTED_LOCATION_RELEASE ${LIBMEM_LIB_DIR}/release/libmem.lib
    IMPORTED_LOCATION ${LIBMEM_LIB_DIR}/release/libmem.lib
    INTERFACE_INCLUDE_DIRECTORIES ${LIBMEM_INCLUDE_DIR}
)

# Common source files
set(COMMON_SOURCES
    src/Injector.cpp
    src/ProcessUtils.cpp
    src/Logger.cpp
)

set(COMMON_HEADERS
    include/Injector.h
    include/ProcessUtils.h
    include/Logger.h
)

# Check for header-only dependencies in external folder
set(EXTERNAL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external)

# Check if external dependencies exist
if(EXISTS ${EXTERNAL_DIR}/json)
    set(ENHANCED_AVAILABLE TRUE)
    message(STATUS "Enhanced features enabled with JSON support")
    message(STATUS "Using header-only libraries from external/ directory")
else()
    message(FATAL_ERROR "JSON dependency not found in external/ directory.")
    message(STATUS "Please run: git clone https://github.com/nlohmann/json.git external/json")
endif()

# Create directories
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Console Version
add_executable(G25F_Injector
    ${COMMON_SOURCES}
    src/Main.cpp
)

# Include directories
target_include_directories(G25F_Injector PRIVATE include)

# Link libraries
target_link_libraries(G25F_Injector 
    kernel32
    user32
    advapi32
    psapi
    ntdll
    libmem::libmem
)

# Compiler flags
if(MSVC)
    target_compile_options(G25F_Injector PRIVATE /W3)
    target_compile_definitions(G25F_Injector PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

message(STATUS "Building console version: G25F_Injector.exe")

# Main backend server
add_executable(G25F_Injector_Backend
    src/backend.cpp
    src/Injector.cpp
    src/ProcessUtils.cpp
    src/Logger.cpp
)

target_include_directories(G25F_Injector_Backend PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/libmem
    ${EXTERNAL_DIR}/json/include
)

# Link libraries for Backend
target_link_libraries(G25F_Injector_Backend
    kernel32
    user32
    advapi32
    psapi
    ntdll
    ws2_32
    libmem::libmem
)

message(STATUS "Building main backend server: G25F_Injector_Backend.exe")

# Compiler flags for Backend
if(MSVC)
    target_compile_options(G25F_Injector_Backend PRIVATE /W3)
    target_compile_definitions(G25F_Injector_Backend PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# Build instructions
message(STATUS "")
message(STATUS "=== G25F Injector Build Configuration ===")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Enhanced Features: ${BUILD_ENHANCED}")
message(STATUS "Enhanced Available: ${ENHANCED_AVAILABLE}")
message(STATUS "")
message(STATUS "GUI: Electron-based interface in electron/ directory")
message(STATUS "Console: Command-line interface (G25F_Injector.exe)")
message(STATUS "Backend: HTTP server with realtime capabilities (G25F_Injector_Backend.exe)")
# Add test framework subdirectory
option(BUILD_TESTS "Build test framework" ON)
if(BUILD_TESTS)
    add_subdirectory(test)
    message(STATUS "Test framework enabled")
endif()

message(STATUS "")
message(STATUS "To build:")
message(STATUS "  1. Create external directory: mkdir external")
message(STATUS "  2. Clone nlohmann/json: git clone https://github.com/nlohmann/json.git external/json")
message(STATUS "  3. Configure and build: cmake .. && cmake --build . --config Release")
message(STATUS "")
message(STATUS "To run Electron GUI:")
message(STATUS "  cd electron && npm start")
message(STATUS "")
message(STATUS "To run tests:")
message(STATUS "  build/Debug/TestRunner.exe or build/Release/TestRunner.exe")
message(STATUS "")
message(STATUS "Backend will auto-start when Electron GUI launches")
message(STATUS "")