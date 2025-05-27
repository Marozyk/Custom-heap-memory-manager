
cmake_minimum_required(VERSION 3.17)
project(project1 C)

set(CMAKE_C_STANDARD 11)

add_compile_options(
      "-fmax-errors=5"
      "-Wno-error=parentheses"
      "-Wextra"
      "-DINSIDE_DANTE"
      "-D_ANSI_OUTPUT"
      "-ggdb3"
      "-std=c11"
      "-pedantic"
      "-Wno-parentheses"
      "-Werror"
      "-fdiagnostics-color"
      "-xc"
      "-Wno-error=unused-parameter"
      "-Wall"
      "-Werror=vla"
      "-D_GNU_SOURCE"
      "-Wno-error=implicit-fallthrough"

)

add_link_options(
        "-Wl,-Map=main.map"
        "-Wl,-cref"
        "-ggdb3"
        "-Wl,-wrap,main"
)

add_executable(project1
        "heap.c"
        "main.c"
)


target_link_libraries(project1
        "pthread"
        "m"
)