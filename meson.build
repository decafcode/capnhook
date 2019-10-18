project('capnhook', 'c', version: '0.2.2')

add_project_arguments(
    '-DCOBJMACROS',
    '-DWIN32_LEAN_AND_MEAN',
    language: 'c',
)

if meson.get_compiler('c').get_argument_syntax() != 'msvc'
    add_project_arguments(
        '-ffunction-sections',
        '-fdata-sections',
        language: 'c',
    )

    add_project_link_arguments(
        '-Wl,--gc-sections',
        '-static-libgcc',
        language: 'c',
    )
endif

inc = include_directories('.')

subdir('hook')
subdir('hooklib')
subdir('inject')
