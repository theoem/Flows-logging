cmake_minimum_required(VERSION 3.16)
project(Flows)

set(CMAKE_CXX_STANDARD 17)

add_executable(Flows main.cpp)

target_link_libraries(Flows PUBLIC protoident)
target_link_libraries(Flows PUBLIC trace)
target_link_libraries(Flows PUBLIC flowmanager)
target_link_libraries(Flows PUBLIC pqxx)
target_link_libraries(Flows PUBLIC pq)
target_link_libraries(Flows PUBLIC pthread)

