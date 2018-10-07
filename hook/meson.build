hook_lib = static_library(
    'hook',
    include_directories : inc,
    c_pch : '../precompiled.h',
    sources : [
        'hr.c',
        'hr.h',
        'pe.c',
        'pe.h',
        'peb.c',
        'peb.h',
        'table.c',
        'table.h',
    ],
)

hook_dep = declare_dependency(
    link_with : hook_lib,
    include_directories : inc,
)
