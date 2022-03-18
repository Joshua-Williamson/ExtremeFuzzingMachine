path := ../libjpeg_ELM_neuzz

compile:
	gcc -O3 -funroll-loops ./neuzz.c -o neuzz
	cp neuzz ${path}

debug:
	gcc -g -O3 -funroll-loops ./neuzz.c -o neuzz_dbg
	cp neuzz_dbg ${path}
	