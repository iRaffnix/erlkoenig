cmake_minimum_required(VERSION 3.10)
project(erlkoenig_rt VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # _GNU_SOURCE for clone(), pivot_root(), etc.

add_executable(erlkoenig_rt
    c-runtime/erlkoenig_rt.c
    c-runtime/erlkoenig_ns.c
    c-runtime/erlkoenig_netcfg.c
    c-runtime/erlkoenig_devfilter.c
    c-runtime/erlkoenig_metrics.c
    c-runtime/erlkoenig_nodecert.c
)

target_include_directories(erlkoenig_rt PRIVATE c-runtime)

# ---------------------------------------------------------------------------
# Compiler warnings -- the compiler is your mom, listen to her
# ---------------------------------------------------------------------------
target_compile_options(erlkoenig_rt PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wshadow
    -Wstrict-prototypes
    -Wold-style-definition
    -Wmissing-prototypes
    -Wmissing-declarations
    -Wno-unused-parameter
    -Wformat=2
    -Wformat-security
    -Wconversion
    -Wsign-conversion
    -Wnull-dereference
    -Wdouble-promotion
    -Wwrite-strings
    -Wcast-align
    -Wredundant-decls
    -Wnested-externs
    -Wswitch-enum
    -Wundef
    -Wvla
)

# GCC-specific warnings (clang ignores unknown -W flags with a warning)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(erlkoenig_rt PRIVATE
        -Wlogical-op
        -Wduplicated-cond
        -Wduplicated-branches
        -Wjump-misses-init
        -Wstringop-overflow=4
        -Wformat-truncation=2
        -Wformat-overflow=2
    )
    # GCC static analyzer (GCC 10+)
    if(CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 10)
        option(ERLKOENIG_ANALYZER "Enable GCC -fanalyzer" OFF)
        if(ERLKOENIG_ANALYZER)
            target_compile_options(erlkoenig_rt PRIVATE -fanalyzer)
        endif()
    endif()
endif()

# ---------------------------------------------------------------------------
# Hardening -- defense in depth
# ---------------------------------------------------------------------------
target_compile_definitions(erlkoenig_rt PRIVATE
    _GNU_SOURCE
    $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>
)

# ---------------------------------------------------------------------------
# Linking: static musl (default) or dynamic glibc (sanitizers only)
# ---------------------------------------------------------------------------
option(ERLKOENIG_SANITIZE "Enable ASan + UBSan (forces dynamic glibc build)" OFF)

# Common hardening for both modes
target_compile_options(erlkoenig_rt PRIVATE
    -fstack-protector-strong
    -fno-strict-aliasing
    $<$<NOT:$<CONFIG:Debug>>:-O2>
    $<$<CONFIG:Debug>:-O0 -g>
)
target_link_options(erlkoenig_rt PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

if(ERLKOENIG_SANITIZE)
    # Sanitizers need dynamic glibc — cannot use musl
    message(STATUS "Sanitizer build: dynamic glibc (ASan + UBSan)")
    target_compile_options(erlkoenig_rt PRIVATE
        -fPIE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(erlkoenig_rt PRIVATE
        -pie
        -fsanitize=address,undefined
    )
else()
    # Default: static musl — zero runtime dependencies
    #
    # musl-gcc looks only in /usr/include/x86_64-linux-musl/.
    # Linux kernel headers need two extra include paths:
    #   /usr/include         — for linux/, asm-generic/
    #   /usr/include/<arch>  — for asm/  (Debian multiarch)
    #
    # -idirafter ensures musl's own headers always take priority.
    # Cleanest alternative: build natively in Alpine container.
    message(STATUS "Static musl build: zero runtime dependencies")
    set(MUSL_KERNEL_HEADERS "/usr/include" CACHE PATH
        "Path to linux kernel headers (linux/, asm-generic/)")
    set(MUSL_ARCH_HEADERS "/usr/include/x86_64-linux-gnu" CACHE PATH
        "Path to arch-specific kernel headers (asm/)")

    target_compile_options(erlkoenig_rt PRIVATE
        -static
        "SHELL:-idirafter ${MUSL_KERNEL_HEADERS}"
        "SHELL:-idirafter ${MUSL_ARCH_HEADERS}"
    )
    target_link_options(erlkoenig_rt PRIVATE -static)
endif()

# ---------------------------------------------------------------------------
# Demo/Test binaries (statically linked container workloads)
# ---------------------------------------------------------------------------
option(ERLKOENIG_BUILD_DEMOS "Build demo/test binaries for integration tests" ON)

if(ERLKOENIG_BUILD_DEMOS)
    set(DEMO_SOURCES
        sleeper echo_server crasher mem_eater disk_writer
        hello_output syscall_fork syscall_mount syscall_write_rootfs
        stdin_echo proc_check
    )

    foreach(demo ${DEMO_SOURCES})
        add_executable(erlkoenig_demo_${demo} c-runtime/demo/${demo}.c)
        set_target_properties(erlkoenig_demo_${demo} PROPERTIES
            OUTPUT_NAME test-erlkoenig-${demo}
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/demo"
        )
        target_compile_options(erlkoenig_demo_${demo} PRIVATE -Wall -Wextra)
        target_link_options(erlkoenig_demo_${demo} PRIVATE -static)

        install(TARGETS erlkoenig_demo_${demo}
            RUNTIME DESTINATION lib/erlkoenig/demo
            COMPONENT demo)
    endforeach()
endif()

# ---------------------------------------------------------------------------
# C-Runtime Unit Tests (libcheck framework)
# ---------------------------------------------------------------------------
#
# Tests exercise each container setup step in isolation with real
# kernel operations (minijail-style). libcheck forks each test
# automatically — critical for tests that do irreversible ops
# (pivot_root, cap drop, seccomp).
#
# Install: apt install check
# Run:     make test-rt        (unprivileged tests only)
#          sudo make test-rt   (all tests including namespace/mount)
#
option(ERLKOENIG_BUILD_TESTS "Build C-runtime unit tests (needs libcheck)" OFF)

if(ERLKOENIG_BUILD_TESTS)
    # Find libcheck: try pkg-config first, fall back to manual search.
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(CHECK check)
    endif()

    if(NOT CHECK_FOUND)
        find_path(CHECK_INCLUDE_DIRS check.h)
        find_library(CHECK_LINK_LIBS check)
        find_library(SUBUNIT_LIB subunit)
        if(CHECK_INCLUDE_DIRS AND CHECK_LINK_LIBS)
            set(CHECK_FOUND TRUE)
            set(CHECK_LIBRARIES ${CHECK_LINK_LIBS})
            if(SUBUNIT_LIB)
                list(APPEND CHECK_LIBRARIES ${SUBUNIT_LIB})
            endif()
            list(APPEND CHECK_LIBRARIES m pthread rt)
        endif()
    endif()

    if(NOT CHECK_FOUND)
        message(FATAL_ERROR "libcheck not found. Install: apt install check")
    endif()

    add_executable(test_container_setup
        c-runtime/test/test_container_setup.c
        c-runtime/erlkoenig_ns.c
        c-runtime/erlkoenig_netcfg.c
    )

    target_include_directories(test_container_setup PRIVATE
        c-runtime
        ${CHECK_INCLUDE_DIRS}
    )

    target_compile_definitions(test_container_setup PRIVATE _GNU_SOURCE)
    target_compile_options(test_container_setup PRIVATE
        -Wall -Wextra -Wno-unused-parameter -g -O0
    )

    target_link_libraries(test_container_setup ${CHECK_LIBRARIES})

    set_target_properties(test_container_setup PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test"
    )
endif()

# ---------------------------------------------------------------------------
# Install targets
# ---------------------------------------------------------------------------
install(TARGETS erlkoenig_rt
    RUNTIME DESTINATION lib/erlkoenig
    COMPONENT runtime)

# Write VERSION file
file(WRITE "${CMAKE_BINARY_DIR}/VERSION" "${PROJECT_VERSION}\n")
install(FILES "${CMAKE_BINARY_DIR}/VERSION"
    DESTINATION lib/erlkoenig
    COMPONENT runtime)

