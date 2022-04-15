import time
import glob
import numpy as np
import sys
import subprocess
from collections import Counter

argvv = sys.argv[1:]
call = subprocess.check_output
crash_dirs=glob.glob('./crashes*')

if __name__ == "__main__":
    for dir in crash_dirs:
        crash_seed_list = glob.glob(dir+"/*")
        ts=time.time()
        raw_bitmap = {}
        tmp_cnt = [] 
        out = ''
        for f in crash_seed_list:
            tmp_list = []
            try:
                out = call(['./afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', "1024", '-t', '1000'] + argvv + [f])
            except subprocess.CalledProcessError as e:
                out=e.output
         
            for line in out.splitlines():
                edge = line.split(b':')[0]
                tmp_list.append(int(edge))
            tmp_cnt.append(tmp_list[-1])
        tmp_cnt=np.array(tmp_cnt)

        crash_unique_bitmap=np.unique(tmp_cnt, axis=0)
        # crash_unique_bitmap=np.unique(crash_unique_bitmap, axis=0)
        print("Findings for" + dir)    
        print("Number of crashes:" + str(len(crash_seed_list)))
        print("Number of unique crashes:" + str(len(crash_unique_bitmap)))
        print("Time" + str(time.time()-ts))
