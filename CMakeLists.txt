project(btmitm)
cmake_minimum_required(VERSION 3.8)

set(CMAKE_C_FLAGS -g)
add_executable(btmitm main.c l2cap.c conn.c hid.c task_sched.c sc.c)
add_executable(l2c l2c.c)
target_link_libraries(btmitm bluetooth)
target_link_libraries(l2c bluetooth pthread)
