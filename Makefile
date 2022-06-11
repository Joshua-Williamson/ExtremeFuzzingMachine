all: afl-utils compile

compile:
	gcc -O3 -funroll-loops ./efm-fuzz.c -o efm-fuzz 

debug:
	gcc -g -O0 -funroll-loops ./efm-fuzz.c -o efm-fuzz-debug 

clean:
	-rm -r bitmaps crashes seeds splice_seeds vari_seeds nocov neuzz neuzz-dbg afl-gcc afl-tmin afl-showmap log_fuzz
	-mkdir seeds

afl-utils:
	$(MAKE) -C AFL_utils
	cp AFL_utils/efm-tmin ./utils/
	cp AFL_utils/afl-showmap ./utils/
	cp AFL_utils/afl-gcc .
