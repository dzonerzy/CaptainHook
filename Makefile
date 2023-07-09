MESON = meson
NINJA = ninja

all-32:
	$(MESON) build -Darch=32 -Dtests=true -Dfcm_test=true
	$(NINJA) -C build

all-64:
	$(MESON) build -Darch=64 -Dtests=true -Dfcm_test=true
	$(NINJA) -C build

all-64-sanitize:
	$(MESON) build -Darch=64 -Dtests=true -Dfcm_test=true -Db_sanitize="address,undefined"
	$(NINJA) -C build

clean:
	$(NINJA) -C build clean
	rmdir /S /Q build
