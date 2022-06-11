import os
import re
from sqlite3 import DataError
import time
import shutil
import shlex
import subprocess
import logging
from turtle import update

import sysv_ipc as ipc
import functools
import socket
import argparse

def add_args():

    parser = argparse.ArgumentParser(description="""Runs the background machine
                        learning process for Neuzz.""")

    parser.add_argument('-e',
                        '--enable-asan',
                        help='Enable ASAN (runs afl-showmap with -m none)',
                        default=False,
                        action='store_true')

    parser.add_argument('-n',
                        '--memory-threshold',
                        help='Maximum amount of nocov seeds allowed',
                        type=int,
                        default=20000)

    parser.add_argument('-q',
                        '--quiet',
                        help='Suppress printing messages, send to log instead',
                        default=False,
                        action='store_true')

    parser.add_argument('-o',
                        '--out-dir',
                        help='working dir for fuzzing',
                        type=str,
                        default="")

    parser.add_argument('target', nargs=argparse.REMAINDER)

    return parser

def init_logger(file_name, verbose=1, name=None, debug=False):
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

    def log_handler(*args,**kwargs):
        logger.info(*args,**kwargs)
        if not debug: print(*args,**kwargs)

    return log_handler

def connect_tcp(log, HOST,PORT):
    #Initalise server config
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Such that the OS releases the port quicker for rapid rerunning
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    #Attatch to ip and port
    sock.bind((HOST, PORT))
    #Waits for neuzz execution
    sock.listen(1)
    log("Waiting for EFM-fuzz connection")
    conn, addr = sock.accept()
    log('Connected to EFM-fuzz on: ' + str(addr))

    return conn 

def time_format(T):
    t_m = (T/ 60) % 60
    t_s = (T) % 60
    return "{:0.0f} min, {:0.0f} sec".format(t_m,t_s)

def get_max_seed_size(seed_path):
    cwd = os.getcwd()
    out = os.popen(f'ls -S {cwd}/{seed_path} | head -1')
    file_path = os.path.join(cwd,seed_path, out.read().split()[0])
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

def EFM_tmin(seed, outfile, bitfile, time_out, threshold_size, target):

    call = subprocess.check_output

    try:
        out = call(['../utils/efm-tmin','-q', '-e', '-i',seed,'-o', outfile ,
                    '-m', '1024', '-t', '1000','-l',str(threshold_size), '-T', str(time_out),
                    '-s', bitfile] + target)
    except subprocess.CalledProcessError as e:
        if e.returncode == '123':
            return False
    
    return True

#Shared memory management 
class SHM(object):
    def __init__(self):
        #Make it so theses keys are the variable/function names 
        self.stats={"status":"Waiting",
                    "accuracy":"-",
                    "bitmap_size":"-",
                    "corpus_size":"-",
                    "nocov_size":"-",
                    "process_bitmaps_time":"-",
                    "reduce_variable_files_time":"-",
                    "last_training":"-",
                    "num_grads":"-"
        }

        #Get this to update the status based on the function name
        self.status_table={"process_bitmaps":"Mapping",
                           "train":"Training",
                           "generate_mutations":"Generating Grads",
                           "wait_fuzzer_data":"Sleeping",
                           "reduce_variable_files":"T-mining",
                           "cull_nocov":"Culling Nocov"
        }
                           

        #Attatch to shared memory from the c module
        self.shm = ipc.SharedMemory(ipc.ftok("/tmp", 6667,silence_warning = True), 0, 0) 
        self.shm.attach(0,0)

        self.update_shm_buff()

    def update_status(self, time_fmt, func, *args, **kwargs):
        
        self.stats["status"] = self.status_table[func.__name__]
        self.update_shm_buff()
        if time_fmt : t_s=time.time()
        ret = func(*args, **kwargs)
        if time_fmt : 
            t_f=time.time()
            t=time_format(t_f-t_s)
            self.stats[func.__name__+"_time"] = t

        self.update_shm_buff()


        return ret

    def update_value(self, name, value):
        
        if not isinstance(value, str):
            value=str(value)

        self.stats[name] = value
        self.update_shm_buff()

        return 


    def update_shm_buff(self):
        
        msg=bytearray()
        for ele in self.stats.values():
            null_pad=40 - (len(ele)+1) 
            msg.extend(ele.encode('utf-8'))
            for i in range(null_pad) :
                msg.append(0)

        self.shm.write(bytes(msg))


def shm_stats(time_fmt = False):
    def dec(func, *args):
        @functools.wraps(func)
        def wrapper_shm(*args, **kwargs):
             return shm_stats.SHM_obj.update_status(time_fmt, func, *args, **kwargs)
        return wrapper_shm
    return dec

@shm_stats(time_fmt=False)
def wait_fuzzer_data(tcp):

    data = tcp.recv(1024)
    if not data:
        raise DataError
    if data[0:3] == b"MAP":
        train = False
    else:
        train = True

    return train

class EFM_vars(object):
    def __init__(self):
        self._accuracy=None
        self._bitmap_size=None
        self._nocov_size=None
        self._num_grads=None
        self._last_training=None
        self._corpus_size=None

        #Setters and properties to update the stats
    #Not that important, ignore till the :)
    @property
    def accuracy(self):
        return self._accuracy

    @accuracy.setter
    def accuracy(self, value):
        self._accuracy=value
        shm_stats.SHM_obj.update_value("accuracy",value)
        return value

    @property
    def bitmap_size(self):
        return self._bitmap_size

    @bitmap_size.setter
    def bitmap_size(self, value):
        self._bitmap_size=value
        shm_stats.SHM_obj.update_value("bitmap_size",value)
        return value

    @property
    def corpus_size(self):
        return self._corpus_size

    @corpus_size.setter
    def corpus_size(self, value):
        self._corpus_size=value
        shm_stats.SHM_obj.update_value("corpus_size",value)
        return value

    @property
    def nocov_size(self):
        return self._nocov_size

    @nocov_size.setter
    def nocov_size(self, value):
        self._nocov_size=value
        shm_stats.SHM_obj.update_value("nocov_size",value)
        return value

    @property
    def num_grads(self):
        return self._num_grads

    @num_grads.setter
    def num_grads(self, value):
        self._num_grads=value
        shm_stats.SHM_obj.update_value("num_grads",value)
        return value
    
    @property
    def last_training(self):
        return self._last_training

    @last_training.setter
    def last_training(self, value):
        self._last_training=value
        shm_stats.SHM_obj.update_value("last_training",value)
        return value
 
    #:)
    