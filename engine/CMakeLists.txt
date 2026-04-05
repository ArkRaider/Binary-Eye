cmake_minimum_required(VERSION 3.14)
project(BinaryEyeEngine)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

# Fetch pe-parse
FetchContent_Declare(
    peparse
    GIT_REPOSITORY https://github.com/trailofbits/pe-parse.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(peparse)

# Fetch nlohmann_json
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

add_executable(engine
    src/main.cpp
    src/Analyzer.cpp
)

target_include_directories(engine PRIVATE src)
target_link_libraries(engine PRIVATE pe-parse nlohmann_json::nlohmann_json)
