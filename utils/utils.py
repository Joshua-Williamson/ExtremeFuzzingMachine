import os
import re
import time
import shutil
import shlex
import subprocess
import logging

import sysv_ipc as ipc
import functools


def init_logger(file_name, verbose=1, name=None):
    level_dict = {0: logging.DEBUG, 1: logging.INFO, 2: logging.WARNING}
    formatter = logging.Formatter(
        "[%(asctime)s][%(filename)s][%(levelname)s] %(message)s"
    )
    logger = logging.getLogger(name)
    logger.setLevel(level_dict[verbose])

    fh = logging.FileHandler(file_name, 'w')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    return logger


def obtain_max_seed_size(seed_path):
    out = os.popen(f'ls -S {seed_path} | head -1')
    file_path = os.path.join(seed_path, out.read().split()[0])
    return os.path.getsize(file_path)


def move_file(src_path, dst_path):
    if not os.path.isfile(src_path):
        return
    fpath, fname = os.path.split(dst_path)
    if not os.path.exists(fpath):
        os.makedirs(fpath)
    shutil.move(src_path, dst_path)


def acquire_edge(showmap_path, seed_path, program_execute):
    showmap_cmd = f'{showmap_path} -q -o /dev/stdout -m 512 -t 500 ./{program_execute} {seed_path}'
    try:
        output = subprocess.check_output(shlex.split(showmap_cmd))
    except subprocess.CalledProcessError:
        return list()
    edge_list = [int(line.split(b':')[0]) for line in output.splitlines()]
    return edge_list


def is_valid_line(line: str):
    if not line.strip():
        return False
    black_list = ['Disassembly', 'file format', '...', '=']
    for item in black_list:
        if item in line:
            return False
    return True


def action(line: str):
    reg_exp = r'.*\t(\w+)\s?'
    match_obj = re.match(reg_exp, line)
    if not match_obj:
        return 'None'
    return match_obj.group(1)

#Shared memory management 
class SHM(object):
    def __init__(self):
        #Make it so theses keys are the variable/function names 
        self.stats={"status":"-",
                    "accuracy":"-",
                    "bitmap_size":"-",
                    "corpus_size":"-",
                    "nocov_size":"-",
                    "last_mapping":"-",
                    "last_reducing":"-",
                    "last_training":"-",
                    "num grads":"-"
        }

        #Get this to update the status based on the function name
        self.status_table={"":"Mapping",
                           "":"Training",
                           "":"Generating Grads",
                           "":"Sleeping",
                           "":"Remapping",
                           "":"T-mining",
                           "":"Culling Nocov"
        }
                           

        #Attatch to shared memory from the c module
        self.shm = ipc.SharedMemory(ipc.ftok("/tmp", 6667,silence_warning = True), 0, 0) 
        self.shm.attach(0,0)

    def __call__(self, func, *args, **kwargs):
        
        if func.__name__ in self.status_table:
            self.stats["status"] = self.status_table[func.__name__]

        else: 
            val = func(*args, **kwargs)
            self.stats[func.__name__] = val

    def update_shm_buff(self):
        
        msg=bytearray()
        for ele in self.stats.values():
            null_pad=40 - (len(ele)+1) 
            msg.extend(ele.encode('utf-8'))
            for i in range(null_pad) :
                msg.append(0)

        self.shm.write(bytes(msg))


def shm_stats(func):
    @functools.wraps(func)
    def wrapper_shm(*args, **kwargs):
        shm_stats.SHM_obj(func, *args, **kwargs)
    return wrapper_shm