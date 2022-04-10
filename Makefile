compile:
	gcc -O3 -funroll-loops ./neuzz.c -o neuzz

debug:
	gcc -g -O3 -funroll-loops ./neuzz.c -o neuzz_dbg

clean:
	rm -r bitmaps crashes seeds splice_seeds vari_seeds
	mkdir seeds