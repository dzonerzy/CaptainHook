fcm_test_raw_sources = [
    'fcm_test.c',
]

fcm_disasm_raw_sources = [
    'fcm_disasm.c',
]


fcm_test_sources = []
fcm_disasm_sources = []

foreach source : fcm_test_raw_sources
  fcm_test_sources += 'fcm_test/' + source
endforeach

foreach source : fcm_disasm_raw_sources
  fcm_disasm_sources += 'fcm_test/' + source
endforeach


fcm_test_inc_dirs = [
  include_directories('../src/fcm/include/'),
]
