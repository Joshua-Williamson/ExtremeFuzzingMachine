one:
	gcc -O3 -funroll-loops ./neuzz.c -o neuzz

debug:
	gcc -O3 -funroll-loops ./neuzz.c -o neuzz_dbg -g