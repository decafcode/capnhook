iohook_lib = static_library(
    'iohook',
    include_directories : inc,
    c_pch : '../precompiled.h',
    sources : [
        'async.c',
        'async.h',
        'chain.c',
        'chain.h',
        'file.c',
        'file.h',
        'iobuf.c',
        'iobuf.h',
        'iohook.c',
        'iohook.h',
        'irp.h',
        'socket.c',
        'socket.h',
    ],
)

iohook_dep = declare_dependency(
    link_with : iohook_lib,
    include_directories : inc,
)
