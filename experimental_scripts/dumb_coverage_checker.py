from enum import unique
import time
import glob
import numpy as np
import sys
import subprocess
import os
from collections import Counter
import shutil
import argparse


argvv = sys.argv[1:]
call = subprocess.check_output

prog_dir={'harfbuzz':['./hb-fuzzer'],
          'libjpeg':['./djpeg'],
          'libxml':['./xmllint'],
          'mupdf':['./mutool','show'],
          'nm':['./nm-new','-C'],
          'objdump':['./objdump','-D'],
          'readelf':['./readelf','-a'],
          'size':['./size']
          }

if __name__ == "__main__":
    orig_dir=os.getcwd()
    for exp in argvv:
        os.chdir(orig_dir)
        print("Experiment:" + str(exp))
        cvg_dirs=glob.glob("./"+exp+'/*')
        for dir in cvg_dirs:
            prog=dir.split('/')[-1].split('_')[0]
            target=prog_dir[prog]
            try:
                os.chdir(orig_dir)
                os.chdir(dir+"/NEUZZ")
                seed_list = glob.glob("./seeds/*")
            except:
                os.chdir(orig_dir)
                os.chdir(dir+"/AFL")
                seed_list = glob.glob("./afl_out/queue/*")
            ts=time.time()
            seen_tups = np.array([],dtype='int')
            out = ''
            for f in seed_list:
                cur_tups= []
                try:
                    out = call([orig_dir+'/afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', "1024", '-t', '1000'] + target + [f])
                except subprocess.CalledProcessError as e:
                    out=e.output
         
                for line in out.splitlines():
                    edge = line.split(b':')[0]
                    cur_tups.append(int(edge))
            
                cur_tups=np.array(cur_tups)
                in_seen_tups=np.in1d(cur_tups,seen_tups)
                not_in_seen_tups=np.invert(in_seen_tups)

                if not_in_seen_tups.any():
                    seen_tups=np.append(seen_tups,cur_tups[not_in_seen_tups])
            
            # crash_unique_bitmap=np.unique(crash_unique_bitmap, axis=0)
            print("\tFindings for" + dir)    
            print("\t \tNumber of tups:" + str(len(seen_tups)))
            print("\t\tTime" + str(time.time()-ts) + "\n")
