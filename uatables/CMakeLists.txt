cmake_minimum_required(VERSION 3.5)
set(PROJECT_NAME UATABLES)
set(TARGET_NAME uatables)
project(${PROJECT_NAME} LANGUAGES CXX VERSION ${GLOBAL_VERSION})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_compile_options(/bigobj)
endif()

file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
    "*.h"
    "*.cpp"
)

add_executable(${TARGET_NAME}
  ${PROJECT_SOURCES}
)

target_include_directories(${TARGET_NAME} PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${PostgreSQL_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${TARGET_NAME}
    ${OPENSSL_LIBRARIES}
    ${Boost_LIBRARIES}
    ${WIN_LINKER_LIBS}
    ${LINUX_LINKER_LIBS}
    ${PostgreSQL_LIBRARY_DIRS}/${PostgreSQL_LIB}
    spdlog
)

install(TARGETS ${TARGET_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
