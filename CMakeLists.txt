cmake_minimum_required(VERSION 3.5)
set(PROJECT_NAME UAUTH)
project(${PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(WIN_LINKER_LIBS
)

set(LINUX_LINKER_LIBS
    -static-libgcc
    -static-libstdc++
    -pthread
)

if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
endif()

#boost
if(WIN32)
    if(MSVC)
        set(BOOST_ROOT "C:/boost_1_82_0_msvc")
        set(BOOST_INCLUDEDIR "C:/boost_1_82_0_msvc/include")
        set(BOOST_LIBRARYDIR "C:/boost_1_82_0_msvc/lib")
    endif()
    if(MINGW)
        if(CMAKE_SIZEOF_VOID_P EQUAL 4)
            #set(BOOST_ROOT "")
            #set(BOOST_INCLUDEDIR "")
            #set(BOOST_LIBRARYDIR "")
        endif()
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            #set(BOOST_ROOT "")
            #set(BOOST_INCLUDEDIR "")
            #set(BOOST_LIBRARYDIR "")
        endif()
    endif()
endif()

if(UNIX AND NOT APPLE)
    set(BOOST_ROOT "/home/$ENV{USER}/boost_1_82_0_gcc")
    set(BOOST_INCLUDEDIR "/home/$ENV{USER}/boost_1_82_0_gcc/include")
    set(BOOST_LIBRARYDIR "/home/$ENV{USER}/boost_1_82_0_gcc/lib")
endif()

set(Boost_DEBUG 1)
set(Boost_USE_STATIC_LIBS ON)

#boost packages
find_package(Boost 1.82.0 EXACT COMPONENTS REQUIRED
    url
    json
    system
    date_time
    filesystem
    program_options
)

#spdlog
set(SPDLOG_MASTER_PROJECT OFF)
set(SPDLOG_INSTALL OFF)
set(SPDLOG_BUILD_SHARED OFF)

#postgresql
if(WIN32)
    set(PostgreSQL_INCLUDE_DIRS "C:\\pgsql\\include")
    set(PostgreSQL_LIBRARY_DIRS "C:\\pgsql\\lib")
    set(PostgreSQL_LIB libpq.lib)
endif()
if(UNIX AND NOT APPLE)
    set(PostgreSQL_INCLUDE_DIRS "/usr/include/postgresql")
    set(PostgreSQL_LIBRARY_DIRS "/usr/lib/x86_64-linux-gnu")
    set(PostgreSQL_LIB libpq.so.5.9)
endif()

find_package(OpenSSL REQUIRED)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/uauth_server)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/uauth_client)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/spdlog-1.9.2)
