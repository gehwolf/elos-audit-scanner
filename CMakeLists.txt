cmake_minimum_required(VERSION 3.10)

set(PLUGIN_VERSION_MAJOR 0)
set(PLUGIN_VERSION_MINOR 1)
set(PLUGIN_VERSION_MICRO 1)
set(PLUGIN_VERSION
    ${PLUGIN_VERSION_MAJOR}.${PLUGIN_VERSION_MINOR}.${PLUGIN_VERSION_MICRO})

project(elos-audit-scanner VERSION ${PLUGIN_VERSION} LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
include(GNUInstallDirs)

find_package(safu 0.54.0 REQUIRED)
find_package(samconf 0.53.1 REQUIRED)
find_package(libelosplugin 1.0.0 REQUIRED)

set(ELOSD_SCANNER_PLUGIN_PATH ${CMAKE_INSTALL_LIBDIR}/elos/scanner/)

set(ELOSD_CONFIG_PATH ${CMAKE_INSTALL_SYSCONFDIR}/elos)
set(ELOSD_SCANNER_CONFIG_PATH ${ELOSD_CONFIG_PATH}/scanner.d)

add_library(scanner_audit
    SHARED
    src/elos_audit_plugin.c
    src/auditd.c
    src/audit.c
)
set_target_properties(scanner_audit PROPERTIES PREFIX "")
set_target_properties(scanner_audit
    PROPERTIES SOVERSION ${PLUGIN_VERSION_MAJOR}
    VERSION ${PLUGIN_VERSION}
)
target_compile_options(scanner_audit
    PRIVATE -O2 -g -Wall -Wextra -pedantic
)
target_compile_definitions(scanner_audit
    PRIVATE SAFU_LOG=1
)
target_link_libraries(scanner_audit
    PUBLIC elos::libelosplugin samconf::samconf safu::safu
)

install(TARGETS scanner_audit DESTINATION ${ELOSD_SCANNER_PLUGIN_PATH})

install(
  FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/audit.json
  DESTINATION
    ${ELOSD_SCANNER_CONFIG_PATH}
)
