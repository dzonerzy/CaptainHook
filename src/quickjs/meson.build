raw_sources = [
    'cutils.c',
    'libbf.c',
    'libregexp.c',
    'libunicode.c',
    'quickjs-libc.c',
    'quickjs.c',
]

qjs_sources = []

foreach source : raw_sources
  qjs_sources += 'src/quickjs/src/' + source
endforeach

qjs_inc_dirs = [
    include_directories('./include'),
]