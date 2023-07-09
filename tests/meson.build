tests_raw_sources = [
    'main.c',
    'tests_a.c',
]

tests_sources = []

foreach source : tests_raw_sources
  tests_sources += 'tests/src/' + source
endforeach

if cc.get_argument_syntax() != 'msvc'
  #enable stack canaries check
  add_project_arguments('-fstack-protector-strong', language : 'c')
else
  add_project_arguments('-fno-stack-protector', language: 'c')
endif

tests_inc_dirs = cpthook_inc_dirs + [
  include_directories('./include'),
]
