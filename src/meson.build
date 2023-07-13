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

subdir('fadec')

sources += fadec_sources

subdir('fcm')

sources += fcm_sources

subdir('quickjs')

sources += qjs_sources