INCS=-Iwinpty/src/include
CFLAGS=${INCS} -shared -O2

winpty.dll: winpty.c
	$(CC) -o $@ $< ${CFLAGS}