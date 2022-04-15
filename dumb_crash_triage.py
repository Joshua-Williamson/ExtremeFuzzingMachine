from enum import unique
import time
import glob
import numpy as np
import sys
import subprocess
import os
from collections import Counter
import shutil

argvv = sys.argv[1:]
call = subprocess.check_output
crash_dirs=glob.glob('./crashes*')

if __name__ == "__main__":
    for dir in crash_dirs:
        os.path.isdir(dir + "_unique/") or os.mkdir(dir + "_unique/")
        shutil.rmtree(dir + "_unique/")
        os.mkdir(dir + "_unique/")
        unique_crashes=0
        crash_seed_list = glob.glob(dir+"/*")
        ts=time.time()
        seen_tups = np.array([],dtype='int')
        out = ''
        for f in crash_seed_list:
            cur_tups= []
            try:
                out = call(['./afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', "1024", '-t', '1000'] + argvv + [f])
            except subprocess.CalledProcessError as e:
                out=e.output
         
            for line in out.splitlines():
                edge = line.split(b':')[0]
                cur_tups.append(int(edge))
            
            cur_tups=np.array(cur_tups)
            in_seen_tups=np.in1d(cur_tups,seen_tups)
            not_in_seen_tups=np.invert(in_seen_tups)

            if not_in_seen_tups.any():
                unique_crashes+=1
                seen_tups=np.append(seen_tups,cur_tups[not_in_seen_tups])
                shutil.copy(f,dir + "_unique/.")
            
        # crash_unique_bitmap=np.unique(crash_unique_bitmap, axis=0)
        print("Findings for" + dir)    
        print("Number of crashes:" + str(len(crash_seed_list)))
        print("Number of unique crashes:" + str(unique_crashes))
        print("Time" + str(time.time()-ts))
