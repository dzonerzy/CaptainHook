project('cpthook', 'c', version : '1.0', default_options : ['warning_level=3', 'c_std=c11'],  meson_version: '>=1.1.0')

# Compiler
cc = meson.get_compiler('c')
python3 = find_program('python3')
nasm = find_program('nasm')

cpthook_inc_dirs = [
  include_directories('src/include/'),
  include_directories('src/fadec/include/'),
]

# Sources
subdir('src')

# Options
if cc.get_argument_syntax() != 'msvc'
  add_project_arguments('-Wno-unused-parameter', language: 'c')
  if get_option('arch') == '32'
    add_project_arguments('-m32', language: 'c')
    add_project_link_arguments('-m32', language: 'c')
  else 
    add_project_arguments('-m64', language: 'c')
    add_project_link_arguments('-m64', language: 'c')
  endif
  add_project_arguments('-Wno-overlength-strings', language: 'c')
  add_project_arguments('-Wno-format', language: 'c')
  add_project_arguments('-fno-stack-protector', language: 'c')
  add_project_arguments('-g', language: 'c')
  # add_project_arguments('-fsanitize=address', language: 'c')
  # add link arguments
  # add_project_link_arguments('-fsanitize=address', language: 'c')
else
  add_project_arguments('/wd4100', language: 'c')
  add_project_arguments('/wd4244', language: 'c')
endif

if get_option('tests')
  subdir('tests')
endif


stub = []

stub += custom_target('cpthook_stub',
  command: [python3, '@INPUT0@',  '-input', '@INPUT1@'] + asm_flags + ['-nasm', nasm],
  input: files('asmcompile.py', asm_source),
  output: ['cpthook_stub.c'],
  install: true,
  install_dir: [false]
)

libcpthook = static_library('cpthook', 
  sources + stub,
  include_directories: cpthook_inc_dirs,
  # cflags 
  c_args: [
    '-fno-stack-protector',
  ],
  install: true,
)

if get_option('tests')
  tests = executable('cpthook_tests', 
    tests_sources,
    include_directories: cpthook_inc_dirs,
    link_with: libcpthook,
    install: false,
  )
endif