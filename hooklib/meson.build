hooklib_lib = static_library(
    'hooklib',
    include_directories : inc,
    c_pch : '../precompiled.h',
    sources : [
        'serial.c',
        'serial.h',
    ],
)

hooklib_dep = declare_dependency(
    link_with : hooklib_lib,
    include_directories : inc,
)
