raw_sources = [
  'cpthook.c',
  'cpthook_utils.c',
  'cpthook_anal.c',
  'cpthook_ir.c',
  'cpthook_temu.c',
]

sources = []

headers = [
  'cpthook.h'
]

foreach source : raw_sources
  sources += 'src/' + source
endforeach

asm_source = []
asm_flags = []

if get_option('arch') == '32'
  asm_source += 'src/cpthook_x86.asm'
  asm_flags += '-x86'
else
  asm_source += 'src/cpthook_x64.asm'
  asm_flags += '-x86_64'
endif

subdir('fadec')

sources += fadec_sources