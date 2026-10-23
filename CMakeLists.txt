cmake_minimum_required(VERSION 3.14)
project(CppYoutubeSearchPlayer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
set(CROW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CROW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    Crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG v1.2.0
)
FetchContent_MakeAvailable(Crow)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(PostgreSQL REQUIRED)

add_executable(youtube_search_app main.cpp)
target_link_libraries(
    youtube_search_app
    PRIVATE
    Crow::Crow
    CURL::libcurl
    OpenSSL::Crypto
    PostgreSQL::PostgreSQL
)
