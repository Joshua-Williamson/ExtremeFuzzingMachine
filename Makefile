CFLAGS_TMIN = -O3 -funroll-loops -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign -DAFL_PATH="/usr/local/lib/afl" -DDOC_PATH="/usr/local/share/doc/afl" -DBIN_PATH="/usr/local/bin"
LDFLAGS_TMIN = -ldl

compile:
	gcc -O3 -funroll-loops ./neuzz.c -o neuzz
	gcc $(CFLAGS_TMIN) afl-tmin.c -o afl-tmin $(LDFLAGS)
debug:
	gcc -g -O3 -funroll-loops ./neuzz.c -o neuzz_dbg

clean:
	rm -r bitmaps crashes seeds splice_seeds vari_seeds
	mkdir seeds