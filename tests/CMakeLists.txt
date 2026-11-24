add_executable(test_runner test_runner.cpp)
target_link_libraries(test_runner PRIVATE rsa_hybrid_core)
lab3_set_warnings(test_runner)

add_test(NAME AllAcceptanceTests COMMAND test_runner)
