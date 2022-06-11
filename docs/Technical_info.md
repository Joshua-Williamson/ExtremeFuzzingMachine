
# Extreme Fuzzing Machine: Technical Information 
## Table of contents 
1. [Introduction](#introduction)
2. [Instrumentation](#paragraph1)
3. [Program Flow](#paragraph2)
    1. [Overview](#subparagraph1)
    2. [Fuzzer](#subparagraph1)
    3. [Neural Network](#NN)

## Instrumentation
 EFM is a coverage guided fuzzer therefore the target must be intrumented such that the fuzzer knows what paths throught the code the fuzzer will execute. So we can save input files that produce diffrent code coverages. We do this using AFL's instrumentation, afl-gcc or afl-g++. It does this by injecting assembly code into the compiler when it detects assembly instructions that will give branching behaviour:

         ^main:      - function entry point (always instrumented)
         ^.L0:       - GCC branch label
         ^.LBB0_0:   - clang branch label (but only in clang mode)
         ^\tjnz foo  - conditional branches

Upon detecting these by looking for any comditional jump assembly instuction, we know where instructions of the code branch. When these instructions are found a 'trampoline' is dumped into the assembly and compiled into the binary. The trampoline can cater to 32-bit or 64-bit instructions:

        /* --- AFL TRAMPOLINE (64-BIT) --- */

        .align 4

        leaq -(128+24)(%rsp), %rsp
        movq %rdx,  0(%rsp)
        movq %rcx,  8(%rsp)
        movq %rax, 16(%rsp)
        movq $0x00003938, %rcx <-- Hard coded random number
        call __afl_maybe_log
        movq 16(%rsp), %rax
        movq  8(%rsp), %rcx
        movq  0(%rsp), %rdx
        leaq (128+24)(%rsp), %rsp

        /* --- END --- */

When afl-gcc dumps the trampoline into the compiler, it hard codes a random number from 0 - 2^16. Which designates the id of the branch that is being currently executed. Which is actually a very poor way of uniquely describiing a branch as in a complex and large code, there will more than likely be more than 65536 branching behaviours, so collisions are very likely. If this is a concern in fuzzing, use alternative instrumnentation developed in AFL++, which protects better against branch id collisions, alternatively modify the MAP_SIZE parameter in afl-gcc, such that the map is bigger.

As we can see one of the first things the trampoline does is load the branch id into the rcx register. Then it calls __afl_maybe_log where it will ultimately execute __afl_store

    __afl_store:

    /* Calculate and store hit for the code location specified in rcx. */

    xorq __afl_prev_loc(%rip), %rcx
    xorq %rcx, __afl_prev_loc(%rip)
    shrq $1, __afl_prev_loc(%rip)

    incb (%rdx, %rcx, 1)

Which does an XOR between the previous and next locations the stores that current location branch id into the __afl_prev_loc variable. When the target code is executed, the fork server has access to a shared memory of the same size of the random number range (MAP_SIZE) of 2^16. The index of the XOR inn the shared memory in incremented by 1. To indicate the the transition between these two branches has occured. If this trainsiton is executed subsequent times, the shared memory array position is incremented. Susinctly:

    cur_location = <COMPILE_TIME_RANDOM>;
    shared_mem[cur_location ^ prev_location]++; 
    prev_location = cur_location >> 1;

The previous location is righthand bit shifted once. Otherwise branch transfers A->B and B->A would be impossible to distinguish. As well as A->A would be the same as B->B. This instrumentation detects the presence of new tuples (branch transitions):

    #1: A -> B -> C -> D -> E
    #2: A -> B -> C -> A -> E

\#1 and \#2 will be classified as unique paths. However this approach is only sensitive to unique tuples or number of times a tuple has been hit. 

 This shared memory is availible to the fuzzer and the fork server executing the program. Such that the fuzzer can analyse the tuple hits. Where, to resist false positives from large hits to tuples that are regularly traversed and not likely to yeild interesting new information a coarse tuple hit counter is used:

    1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+ 
  
Where executions give a tuple count(s) that are in a bins larger than that seen by previous executions are considered unique. For more information please checkout EFM/AFL_utils/docs/technical_details.txt or take a look at EFM/AFL_utils/afl-as.c to see what is actually going on.

## Program Flow : 
### 1. Overview
The program is split into two parts, the fuzzer module written in c. And the neural network module the is written in python. The two modules are run in parallel and communicate using TCP messages and also have an small area of shared memory where stats from the python module can be send to the fuzzer. The fuzzer is the primary program that is executed initially, and spawns the python process itself.

If the python module is misbehaving and you need to debug it, add -d into the arguments to efm-fuzz, this disables it from being automatically being spawned. Spawn the python process in a seperate shell within a debugger manually, it will wait for a TCP message from efm-fuzz, efm-fuzz should be executed after the python debugger is launched.

The fuzzer does the work executing and analysing the executions, finding intersting seeds, hangs and crashes. The neural network, advises the fuzzer which bytes of the input file are worth mutating to find interesting seeds.

### 2. Fuzzing with efm-fuzz.c
 The output directory contains these folders:

- crashes
- edges
- flow
- hangs
- havoc_seeds
- nocov
- seeds
- vari_seeds


Program flow overview: 

- Set up output dirs, allocate shared memory for fork servers and python module

- Copies over seeds from input into output directory

- Sets up fork server to execute the target program

- Spawn python module and check it's alive and well

- Dry runs inputed seeds to populate the shared memory bitmap so we know what tuple hits we already have.

- Sends a signal to the nn module to generate some gradients from the nerual net trained on the dry runned seeds we inputed, giving positions and byte directions (+'ve or -'ve) to mutate a given seed file.

- For each line of the gradient file the pytohn module passes, the mutations are ran on the target file, looking for interesting tuple hits, hangs or crashes. 

- Some random insertion and deletion suppliments the mutation, guided by the locations provided by the nn module.

- After all lines have been processed, the fuzzer conducts a havoc stage, which is a feature taken from AFL and improved by Wu et. al and is extremely effective at generating new edge coverage.

- Signal is then send to the nn module to retrain on current seed data from the last fuzzing round and produce more gradients.

- The process is repeated until the user stops the fuzzer

The output directory contains these folders:

- **crashes**: seeds that trigger crashes in the target program by triggering unique tuple counts

- **edges**: Each seed has a file containing the hit count of every tuple in the execution of an interesting seed

- **flow**: Information about edge context in the target program are stored here

- **hangs**: Seeds that trigger time outs in the target program by triggering unique tuple counts

- **havoc_seeds**: Seeds found by the AFL havoc stage that are too large to go in seeds 

- **nocov**: Randomly saves seed files that give no extra coverage, to augment the dataset fed to the neural network.

- **seeds**: Target program input files that find interesting tuple hits.

- **vari_seeds**: Seeds found by the random insertion and deletion stage of fuzzing. As they are frequently too large to keep in the seeds folder.


### 3. AI with nn.py