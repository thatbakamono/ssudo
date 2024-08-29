project(ssudo)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ssudo src/main.cpp)
target_link_libraries(ssudo PRIVATE pam)
