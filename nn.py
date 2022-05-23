#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import glob
import math
import time
import random
import socket
import subprocess
import numpy as np
from collections import Counter

from pyparsing import lineEnd

from utils.flow import FlowBuilder
import torch
from torch.autograd import Variable
from utils.TorchELM import pseudoInverse 

#Setting up ip and port for internal server
HOST = '127.0.0.1'
PORT = 12012

round_cnt = 0
# Choose a seed for random initilzation
# seed = int(time.time())

#Fixed seed
seed = 12
np.random.seed(seed)
random.seed(seed)
# get binary argv
argvv = sys.argv[1:]

def parse_executable():
    global correspond_dict

    flow = FlowBuilder(args.target[0])
    with open(flow.correspond_target, 'r') as fopen:
        correspond_dict = eval(fopen.readline())

def process_data_parallel():

    global MAX_BITMAP_SIZE
    global MAX_FILE_SIZE
    global SPLIT_RATIO
    global seed_list
    global nocov_list
    global new_seeds
    global len_seed_list
    global len_nocov_list
    global label

    call = subprocess.check_output

    new_seeds = glob.glob('./seeds/id_*')
    old_seed_list=seed_list
    old_nocov_list=nocov_list
    seed_list=glob.glob('./seeds/*')
    nocov_list=glob.glob('./nocov/*')
    len_seed_list,len_nocov_list = len(seed_list),len(nocov_list)
    to_map_seed_list=list(set(seed_list).difference(old_seed_list))+(list(set(nocov_list).difference(old_nocov_list)))
    SPLIT_RATIO=len(seed_list)+len(nocov_list)

    out = ''
    warning = False
    pad=0
    bitmaps=np.empty([len(to_map_seed_list),MAX_BITMAP_SIZE])
    for ind,f in enumerate(to_map_seed_list):
        tmp_list = [] #Keeps list of ID's for each seed file inside loop
        try:
            # append "-o tmp_file" to strip's arguments to avoid tampering tested binary.
            mem_lim= '1024' if not args.enable_asan else 'none'
            if argvv[0] == './strip':
                raise NotImplementedError
                out = call(['./afl-showmap', '-q', '-e', '-o', '/dev/stdout', '-m', '512', '-t', '500'] + argvv + [f] + ['-o', 'tmp_file'])
            else:
                out = call(['./utils/afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', mem_lim, '-t', '1000'] + args.target + [f])
        except subprocess.CalledProcessError as e:
            if not warning:
                print('\nNon-zero exit status, don\'t panic! \nProbably a hanging execution but run again with showmap with a longer timeout or with ASAN to be sure! \n')
                warning = True 
            print('Warning : showmap returns non-zero exit status for seed: {0}'.format(f)) 
            #raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))

        for line in out.splitlines():
            edge = line.split(b':')[0]
            tmp_list.append(int(edge))
        
        tmp_list=np.array(tmp_list)
        not_seen_already=np.invert(np.in1d(tmp_list,label))
        pad+=sum(not_seen_already)
        bitmaps=np.pad(bitmaps,[(0,0),(0,sum(not_seen_already))], mode='constant')
        label=np.append(label,tmp_list[not_seen_already])

        bitmaps[ind]=np.in1d(label,tmp_list).astype('int')

    print("data dimension" + str(bitmaps.shape))

    old_bitmaps=glob.glob("./bitmaps/*")
    for bitmap in old_bitmaps:
        tmp=np.load(bitmap)
        tmp=np.pad(tmp,[(0,pad)],mode='constant')
        np.save(bitmap,tmp)

    # save training data
    MAX_BITMAP_SIZE = bitmaps.shape[1] 
    for idx, i in enumerate(to_map_seed_list):
        file_name = "./bitmaps/" + i.split('/')[-1]
        np.save(file_name, bitmaps[idx])

def reduce_variable_files():

    global vari_seed_list
    global havoc_seed_list

    if round_cnt != 1:
        old_vari_seed_list=vari_seed_list
        old_havoc_seed_list=havoc_seed_list
    else:
        old_vari_seed_list=[]
        old_havoc_seed_list=[]

    vari_seed_list = glob.glob('./vari_seeds/*')
    havoc_seed_list = glob.glob('./havoc_seeds/*')
    minimise_seed_list =list(set(vari_seed_list).difference(old_vari_seed_list))+(list(set(havoc_seed_list).difference(old_havoc_seed_list))) 

    call = subprocess.check_output

    warning=False
    for f in minimise_seed_list:
        outfile = "./seeds/"+f.split('/')[-1]+'min'
        try:
            out = call(['timeout','10s','./utils/afl-tmin','-q', '-e', '-i',f,'-o', outfile , '-m', '1024', '-t', '1000','-l',str(MAX_FILE_SIZE)] + args.target)
        except subprocess.CalledProcessError as e:
            if not warning:
                print('\nNon-zero exit status, don\'t panic! \nProbably a hanging execution but run again with showmap with a longer timeout or with ASAN to be sure! \n')
                warning = True 
            print('Warning : t-min returns non-zero exit status for seed: {0}'.format(f)) 

def cull_nocov():
    global nocov_list
    global len_nocov_list
    global SPLIT_RATIO

    cull_number=(len_nocov_list+len_seed_list)-args.memory_threshold
    if cull_number > 0:
        try:
            deletes=np.random.choice(nocov_list,cull_number,replace=False)
        except:
            deletes=[]
        for file in deletes:
            os.remove(file)
    
        nocov_list=[x for x in nocov_list if x not in deletes]
        len_nocov_list=len(nocov_list)
        SPLIT_RATIO=len(seed_list)+len(nocov_list)


# process training data from afl raw data
def process_data_init():
    #Max seed input file size allowed
    MAX_MAX_FILE_SIZE = 10000
    MAX_MAX_BITMAP_SIZE = 2000

    global MAX_BITMAP_SIZE
    global MAX_FILE_SIZE
    global SPLIT_RATIO
    global seed_list
    global nocov_list
    global new_seeds
    global label
    global len_seed_list

    parse_executable()

    # shuffle training samples
    seed_list = glob.glob('./seeds/*')
    len_seed_list = len(seed_list)
    seed_list.sort()
    SPLIT_RATIO = len(seed_list)
    rand_index = np.arange(SPLIT_RATIO)
    np.random.shuffle(seed_list)
    new_seeds = glob.glob('./seeds/id_*')

    call = subprocess.check_output

    # get MAX_FILE_SIZE
    cwd = os.getcwd()
    max_file_name = call(['ls', '-S', cwd + '/seeds/']).decode('utf8').split('\n')[0].rstrip('\n')
    MAX_FILE_SIZE = os.path.getsize(cwd + '/seeds/' + max_file_name)

    # create directories to save label, spliced seeds, variant length seeds, crashes and mutated seeds.
    os.path.isdir("./bitmaps/") or os.makedirs("./bitmaps")
    os.path.isdir("./havoc_seeds/") or os.makedirs("./havoc_seeds")
    os.path.isdir("./vari_seeds/") or os.makedirs("./vari_seeds")
    os.path.isdir("./crashes/") or os.makedirs("./crashes")
    os.path.isdir("./hangs/") or os.makedirs("./hangs")
    os.path.isdir("./nocov/") or os.makedirs("./nocov")
    nocov_list=glob.glob('./nocov/*')

    # obtain raw bitmaps
    warning = False
    raw_bitmap = {} #Is a dictionary for each seed file key containing the sequential ID's of each branch it covered
    tmp_cnt = [] #Hold's ID's cumlatively for each seed input
    out = ''
    for f in seed_list:
        tmp_list = [] #Keeps list of ID's for each seed file inside loop
        try:
            # append "-o tmp_file" to strip's arguments to avoid tampering tested binary.
            mem_lim= '1024' if not args.enable_asan else 'none'
            if argvv[0] == './strip':
                raise NotImplementedError
                out = call(['./afl-showmap', '-q', '-e', '-o', '/dev/stdout', '-m', '512', '-t', '500'] + argvv + [f] + ['-o', 'tmp_file'])
            else:
                out = call(['./utils/afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', mem_lim, '-t', '1000'] + args.target + [f])
        except subprocess.CalledProcessError as e:
            if not warning:
                print('\nNon-zero exit status, don\'t panic! \nProbably a hanging execution but run again with showmap with a longer timeout or with ASAN to be sure! \n')
                warning = True 
            print('Warning : showmap returns non-zero exit status for seed: {0}'.format(f)) 
            #raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))

        #Takes the first arg of each tuple generated 
        #I.e Collecting A -> B -> C -> D -> E (tuples: AB, BC, CD, DE) = [ A , B, C, D, E ]
        for line in out.splitlines():
            edge = line.split(b':')[0]
            tmp_cnt.append(edge)
            tmp_list.append(edge)
        raw_bitmap[f] = tmp_list
    counter = Counter(tmp_cnt).most_common() #Counts the occurances of each edge (ID) [('ID',No.),...] ordered in decending order 

    # save bitmaps to individual numpy label
    # creates array of N_seed x Total edges found and for each seed assigns a one for an edge it touches and 0 if not
    label = [int(f[0]) for f in counter]
    bitmap = np.zeros((len(seed_list), len(label)))
    for idx, i in enumerate(seed_list):
        tmp = raw_bitmap[i]
        for j in tmp:
            if int(j) in label:
                bitmap[idx][label.index((int(j)))] = 1

    # label dimension reduction
    # Kinda weird indepnedent of edge value reduces the bitmap to the different ways each seed can cross each edge
    fit_bitmap = bitmap
    print("data dimension" + str(fit_bitmap.shape))

    # save training data
    MAX_BITMAP_SIZE = fit_bitmap.shape[1]
    for idx, i in enumerate(seed_list):
        file_name = "./bitmaps/" + i.split('/')[-1]
        np.save(file_name, fit_bitmap[idx])
    
    label=np.array(label)


# training data generator
def generate_training_data(lb, ub):
    seed = np.zeros((ub - lb, MAX_FILE_SIZE))
    bitmap = np.zeros((ub - lb, MAX_BITMAP_SIZE))
    train_list=seed_list+nocov_list
    for i in range(lb, ub):
        tmp = open(train_list[i], 'rb').read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
        seed[i - lb] = [j for j in bytearray(tmp)]

    for i in range(lb, ub):
        file_name = "./bitmaps/" + train_list[i].split('/')[-1] + ".npy"
        bitmap[i - lb] = np.load(file_name)
    return seed, bitmap


# learning rate decay
def step_decay(epoch):
    initial_lrate = 0.001
    drop = 0.7
    epochs_drop = 10.0
    lrate = initial_lrate * math.pow(drop, math.floor((1 + epoch) / epochs_drop))
    return lrate

def train_generate(batch_size):
    global seed_list
    global nocov_list
    np.random.shuffle(seed_list)
    np.random.shuffle(nocov_list)
    # load a batch of training data
    for i in range(0, SPLIT_RATIO, batch_size):
        # load full batch if batchsize is greater than the seeds availible
        if (i + batch_size) > SPLIT_RATIO:
            x, y = generate_training_data(i, SPLIT_RATIO)
            y=y*2-1
            x = x.astype('float32') / 255
        # load remaining data for last batch
        else:
            x, y = generate_training_data(i, i + batch_size)
            y=y*2-1
            x = x.astype('float32') / 255
        yield (torch.Tensor(x), torch.Tensor(y))


# get vector representation of input
def vectorize_file(fl):
    seed = np.zeros((1, MAX_FILE_SIZE))
    tmp = open(fl, 'rb').read()
    ln = len(tmp)
    if ln < MAX_FILE_SIZE:
        tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
    seed[0] = [j for j in bytearray(tmp)]
    seed = seed.astype('float32') / 255
    seed = torch.from_numpy(seed)
    seed.requires_grad=True
    return seed

# compute gradient for given input
# taking gradient of randomly selected bitmap output at randomly selected input
def gen_adv2(f, fl, optimizer ):
    adv_list = []
    x = vectorize_file(fl)
    K=optimizer.RBF_Kernel(x,optimizer.data)
    out=torch.mm(K,optimizer.Net)[:,f]
    grads_value = torch.autograd.grad(out,x)[0].numpy()
    idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
    val = np.sign(grads_value[0][idx])
    adv_list.append((idx, val, fl))
        
    return adv_list


# compute gradient for given input without sign
def gen_adv3(f, fl, optimizer ):
    adv_list = []

    x = vectorize_file(fl)
    K=optimizer.RBF_Kernel(x,optimizer.data)
    out=torch.mm(K,optimizer.Net)[:,f]
    grads_value = torch.autograd.grad(out,x)[0].numpy()
    idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
    #val = np.sign(grads_value[0][idx])
    val = np.random.choice([1, -1], MAX_FILE_SIZE, replace=True)
    adv_list.append((idx, val, fl))

    return adv_list


# grenerate gradient information to guide furture muatation
def gen_mutate2(optimizer, edge_num, sign):
    
    #model=Keras model, Edge_num=of paths to smaple as 'interesting', sign=True if train false if not
    
    tmp_list = []

    # function pointer for gradient computation
    fn = gen_adv2 if sign else gen_adv3

    # select output neurons to compute gradient
    interested_indice = select_edges(edge_num)

    with open('gradient_info_p', 'w') as f:
        for edg_idxx, seed_indxx in interested_indice:
            fl=seed_list[seed_indxx]
            #print("number of feature " + str(idxx))
            adv_list = fn(edg_idxx, fl, optimizer )
            tmp_list.append(adv_list)
            #Basically takes random inputs from the seed files and considers their gradient on a randomly selected
            #bitmap and returns the gradients of each input byte w.r.t output 
            for ele in adv_list:
                ele0 = [str(el) for el in ele[0]]
                ele1 = [str(int(el)) for el in ele[1]]
                ele2 = ele[2]
                f.write(",".join(ele0) + '|' + ",".join(ele1) + '|' + ele2 + "\n")


def build_model():

    optimizer= pseudoInverse(SPLIT_RATIO,C=0.001,L=0,sigma=500.0,is_cuda=args.enable_cuda)
    if args.enable_cuda:
        optimizer.to(device)#<-Will this work?

    return optimizer

def accur_1(y_true, y_pred):
    y_true = torch.sign(y_true - 1e-6)#Make better
    pred =torch.sign(y_pred - 1e-6) 
    summ = MAX_BITMAP_SIZE
    right_num =torch.sum(torch.eq(y_true,pred),dim=1) 
    wrong_num = summ-right_num
    return torch.mean(right_num/(right_num+wrong_num))

def train(optimizer):
    batch_size=SPLIT_RATIO
    init = time.time()
    for batch_idx, (data, target) in enumerate(train_generate(batch_size)):
        if args.enable_cuda:
            data, target = data.cuda(), target.cuda()
        data, target = Variable(data,requires_grad=False), \
                       Variable(target.type(torch.float32),requires_grad=False)
        optimizer.data=data
        optimizer.train(inputs=data, targets=target)
        output = torch.mm(optimizer.K.T,optimizer.Net)
        acc=accur_1(target,output)

    ending = time.time()
    print('Training time: {:.2f}sec/ Training Accuracy: {:.2f}'.format(ending - init,acc))

def gen_grad(data):
    global round_cnt
    t0 = time.time()
    optimizer = build_model()
    train(optimizer)
    #100-> 200 mutation cases?
    gen_mutate2(optimizer, 100, data[:5] == b"train") #500 -> 100 in paper
    round_cnt = round_cnt + 1
    #print(time.time() - t0)

def select_edges(edge_num):
    # candidate edges
    if np.random.rand() < 0.1:
        # random selection mechanism
        alter_edges = np.random.choice(MAX_BITMAP_SIZE, edge_num)
        alter_seeds = np.random.choice(len_seed_list, edge_num).tolist()
    else:
        candidate_set = set()
        for edge in label:
            if check_select_edge(edge):
                candidate_set.add(list(label).index(edge))
        replace_flag = True if len(candidate_set) < edge_num else False
        alter_edges = np.random.choice(list(candidate_set), edge_num, replace=replace_flag)
        alter_seeds = np.random.choice(len_seed_list, edge_num).tolist()

        for i,(seed_indx,interest_ind) in enumerate(zip(alter_seeds,alter_edges)):
            seed=seed_list[seed_indx]
            seed_bits=np.load("./bitmaps/" + seed.split('/')[-1] + ".npy")
            seed_inds=np.where(seed_bits==1)[0]
            if not interest_ind in list(seed_inds):
                candidates=list(candidate_set.intersection(seed_inds))    
                if candidates:
                    alter_edges[i]=np.random.choice(candidates)
                else:
                    alter_edges=np.delete(alter_edges,i)
                    alter_seeds=np.delete(alter_seeds,i)
    # random seed list
    #TODO:
    #Adding table so that seeds and indices arent repeated
    #Add additional check here to see if edge is in the path of seed file 
    #Also focus on opitmising the gradient stuff and I think that will be everything
    #Is nocov wasting time on seeds that will never get passed? 


    interested_indice = zip(alter_edges.tolist(), alter_seeds)
    return interested_indice


def check_select_edge(edge_id):
    SELECT_RATIO = 0.4
    if edge_id not in correspond_dict.keys():
        return True
    
    correspond_set = correspond_dict[edge_id]
    if len(correspond_set) == 0:
        return True

    cover_cnt = 0
    for ce in correspond_set:
        if ce in label:
            cover_cnt += 1
    if cover_cnt / len(correspond_set) > SELECT_RATIO:
        return False
    return True


def setup_server():
    #Initalise server config
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #Such that the OS releases the port quicker for rapid rerunning
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    #Attatch to ip and port
    sock.bind((HOST, PORT))
    #Waits for neuzz execution
    sock.listen(1)
    print("Waiting for neuzz engine")
    conn, addr = sock.accept()
    print('Connected by neuzz engine ' + str(addr))
    t0=time.time()
    process_data_init()
    print("Initial map in: " + str(time.time()-t0) + " seconds")
    gen_grad(b"train")
    conn.sendall(b"start")
    while True:
        print("Sleeping")
        data = conn.recv(1024)
        if not data:
            break
        else:
            if data[0:3] == b"MAP":
                print("Remapping")
                t0=time.time()
                reduce_variable_files()
                process_data_parallel()
                cull_nocov()
                print("Remapped in: " + str(time.time()-t0) + " seconds")
            else:
                print("Retraining")
                t0=time.time()
                reduce_variable_files()
                process_data_parallel()
                cull_nocov()
                print("Remapped in: " + str(time.time()-t0) + " seconds")
                gen_grad(data)
                conn.sendall(b"start")
    conn.close()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="""Runs the background machine
                        learning process for Neuzz.""")

    parser.add_argument('-e',
                        '--enable-asan',
                        help='Enable ASAN (runs afl-showmap with -m none)',
                        default=False,
                        action='store_true')
                    
    parser.add_argument('-c',
                        '--enable-cuda',
                        help='Enables cuda functionality on training',
                        default=False,
                        action='store_true')

    parser.add_argument('-n',
                        '--memory-threshold',
                        help='Maximum amount of nocov seeds allowed',
                        type=int,
                        default=20000)


    parser.add_argument('target', nargs=argparse.REMAINDER)
    global args
    global device
    args = parser.parse_args()
    if args.enable_cuda:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        print("Using Device: " + str(device))
    #Start program and spin up server
    setup_server()
