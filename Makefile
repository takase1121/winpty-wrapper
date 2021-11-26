CFLAGS=-shared

STRIP?=strip

debug: CFLAGS += -g -O0
debug: winpty.dll

release: CFLAGS += -O2
release: winpty.dll
	$(STRIP) --strip-unneeded $<

winpty.dll: winpty.c util.h
	$(CC) -o $@ $< ${CFLAGS}

doc:
	mkdir -p share/doc/winpty
	cp LICENSE share/doc/winpty/LICENSE.md
	cp README.md share/doc/winpty/README.md

pre-dist: release doc
	mkdir -p bin
	cp winpty.dll bin

dist: pre-dist
	tar -czf winpty-${MSYSTEM_CARCH}-$$(git describe --exact-match --tags 2> /dev/null || git rev-parse --short HEAD).tar.gz bin include share

clean:
	rm -rf bin
	rm -rf share
	rm -f *.dll *.tar.gz

.PHONY: debug release doc pre-dist dist clean