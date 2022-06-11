# Extreme Fuzzing Machine (EFM): using Extreme Learning Machines for gradient guided fuzzing

By Joshua Williamson. Any questions, please email me at 1joshua.williamson@gmail.com !


<p float="left">
  <img src="docs/start_up.jpg?raw=true" width="400" />
  <img src="docs/screen.jpg?raw=true" width="400" /> 
</p>

## Acknowledgements:
 This fuzzer is a modified and improved version of the fuzzer NEUZZ, developed by DongDongShe et. all: <br/>
 - Github: https://github.com/Dongdongshe/neuzz
 - Paper: https://arxiv.org/abs/1807.05620

This repository also includes improvments developed by Wu et. al:  <br/>
- Github: https://github.com/PoShaung/program-smoothing-fuzzing
- Paper 1: http://zhangyuqun.com/publications/icse2022b.pdf
- Paper 2: http://zhangyuqun.com/publications/icse2022a.pdf

Additionally many of the other improvement include a lot of code repurposed from American Fuzzy Lop (AFL) by Zalewski et. al:<br/>
- Github: https://github.com/google/AFL

## Brief Introduction :
 EFM leverages the speed of Extreme Learning Machines as neural networks to perform gradient guided fuzzing without the overhead of high end GPU hardware to train the neural network in this gradinen guided approach. For more info, please refer to the docs.

 Improvements on the usability and quality of life improvents have been made upon the orignal NEUZZ program.

## Requirements : 

 This program has been tested on Ubuntu 20.04, although it should work on most conventional distro's. I advise you run this on a VM or some burner hardware as fuzzing in general is bad for your hard drive. Or, run with the output directory on a ramdisk.

- Python 3.9 (> 3.7 will be fine)
- Pytorch 
- Numpy 
- sysv-ipc

For the easy way do: $ pip install -r requirements.txt
```bash
$ pip install -r requirements.txt
```

## Build :
Build this repo by cloning and then:
```bash
$ cd EFM
$ make 
```
This should build successfully, with no error messages and be all ready to go for fuzzing. If not, email me.
## Usage :
### 1. Instrument your binary:
 First, so we can fuzz the target binary, we have to instument it. So if your program is a basic standalone c or c++ file. You can use either

```bash
$ afl-gcc <target.c> -o <binary name> -<C FLAGS>
$ afl-g++ <target.cpp> -o <binary name> -<CPP FLAGS>
```
Alternatively if the program is large and a option to run a configure script:

```bash
$ CC=/path/to/afl/afl-gcc ./configure
or 
$ CXX=/path/to/afl/afl-g++ ./configure
$ make clean all
```

Refer to the INSTRUMENTATION section in the docs of AFL for useful info

### 2. Collect some fuzzing cases:
 For the fastest results, have a couple of hundred or more test cases to feed to EFM. If you only have one, it's fine. Just run AFL on it for an hour or so to get some cases, then copy the queue from AFL to the directory you want to input to EFM. Or just give EFM the one test case, but it will be slow to explore the program initially.

```bash
$ cp -a <afl-out-dir>/queue <EFM-in-dir>
```

### 3. Start Fuzzing 
Now you can finally begin, make an directory you would like to output the results to. And run the fuzzer.

```bash
$ ./efm-fuzz -i <EFM-in-dir> -o <EFM-out-dir> -- </path/to/program> <--program --args> @@
```

NOTE: Every time you run efm-fuzz it will overwrite your results direcrtory so saves any fuzzing campaigns you embark upon!

## Sample programs :
 There are 10 sample programs with test cases ready to go in EFM in the './programs' folder, provided courtesy of NEUZZ.
