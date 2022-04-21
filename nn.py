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

import torch
from torch.autograd import Variable
from TorchELM import pseudoInverse 

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
seed_list = glob.glob('./seeds/*')
new_seeds = glob.glob('./seeds/id_*')
SPLIT_RATIO = len(seed_list)
# get binary argv
argvv = sys.argv[1:]


# process training data from afl raw data
def process_data():
    #Max seed input file size allowed
    MAX_MAX_FILE_SIZE = 10000
    MAX_MAX_BITMAP_SIZE = 2000

    global MAX_BITMAP_SIZE
    global MAX_FILE_SIZE
    global SPLIT_RATIO
    global seed_list
    global new_seeds

    # shuffle training samples
    seed_list = glob.glob('./seeds/*')
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

    #Removes files over threshold
    while round_cnt == 0 and MAX_FILE_SIZE > MAX_MAX_FILE_SIZE:
        os.remove(cwd + '/seeds/' + max_file_name)
        max_file_name = call(['ls', '-S', cwd + '/seeds/']).decode('utf8').split('\n')[0].rstrip('\n')
        MAX_FILE_SIZE = os.path.getsize(cwd + '/seeds/' + max_file_name)

    # create directories to save label, spliced seeds, variant length seeds, crashes and mutated seeds.
    os.path.isdir("./bitmaps/") or os.makedirs("./bitmaps")
    os.path.isdir("./havoc_seeds/") or os.makedirs("./havoc_seeds/")
    os.path.isdir("./vari_seeds/") or os.makedirs("./vari_seeds")
    os.path.isdir("./crashes/") or os.makedirs("./crashes")

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
                out = call(['./afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', mem_lim, '-t', '1000'] + args.target + [f])
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


# training data generator
def generate_training_data(lb, ub):
    seed = np.zeros((ub - lb, MAX_FILE_SIZE))
    bitmap = np.zeros((ub - lb, MAX_BITMAP_SIZE))
    for i in range(lb, ub):
        tmp = open(seed_list[i], 'rb').read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
        seed[i - lb] = [j for j in bytearray(tmp)]

    for i in range(lb, ub):
        file_name = "./bitmaps/" + seed_list[i].split('/')[-1] + ".npy"
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
    np.random.shuffle(seed_list)
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


# Details are @ https://blog.birost.com/a?ID=00700-6b1d1b35-2c3f-4a07-9c3d-9c319798c6ef in splice section
# splice two seeds to a new seed
def splice_seed(fl1, fl2, idxx):
    tmp1 = open(fl1, 'rb').read()
    ret = 1
    randd = fl2
    while ret == 1:
        tmp2 = open(randd, 'rb').read()
        if len(tmp1) >= len(tmp2):
            lenn = len(tmp2)
            head = tmp2
            tail = tmp1
        else:
            lenn = len(tmp1)
            head = tmp1
            tail = tmp2
        f_diff = 0
        l_diff = 0

        #lenn is the longest seed 
        for i in range(lenn):
            if tmp1[i] != tmp2[i]:
                f_diff = i
                break
        for i in reversed(range(lenn)):
            if tmp1[i] != tmp2[i]:
                l_diff = i
                break

        #Is this because the shorter inputs are null byte padded on the right ?
        if f_diff >= 0 and l_diff > 0 and (l_diff - f_diff) >= 2:
            splice_at = f_diff + random.randint(1, l_diff - f_diff - 1)
            head = list(head)
            tail = list(tail)
            tail[:splice_at] = head[:splice_at]
            with open('./splice_seeds/tmp_' + str(idxx), 'wb') as f:
                f.write(bytearray(tail))
            ret = 0
        print("Splice_info:",f_diff, l_diff)
        randd = random.choice(seed_list)


# compute gradient for given input
# taking gradient of randomly selected bitmap output at randomly selected input
def gen_adv2(f, fl, optimizer, idxx, splice,edge_num):
    adv_list = []
    ll = 2
    while fl[0] == fl[1]:
        fl[1] = random.choice(seed_list)

    for index in range(ll):
        x = vectorize_file(fl[index])
        K=optimizer.RBF_Kernel(x,optimizer.data)
        out=torch.mm(K,optimizer.Net)[:,f]
        grads_value = torch.autograd.grad(out,x)[0].numpy()
        idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
        val = np.sign(grads_value[0][idx])
        adv_list.append((idx, val, fl[index]))

    return adv_list


# compute gradient for given input without sign
def gen_adv3(f, fl, optimizer, idxx, splice, edge_num):
    adv_list = []
    ll = 2
    while fl[0] == fl[1]:
        fl[1] = random.choice(seed_list)

    for index in range(ll):
        x = vectorize_file(fl[index])
        K=optimizer.RBF_Kernel(x,optimizer.data)
        out=torch.mm(K,optimizer.Net)[:,f]
        grads_value = torch.autograd.grad(out,x)[0].numpy()
        idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
        #val = np.sign(grads_value[0][idx])
        val = np.random.choice([1, -1], MAX_FILE_SIZE, replace=True)
        adv_list.append((idx, val, fl[index]))

    return adv_list


# grenerate gradient information to guide furture muatation
def gen_mutate2(optimizer, edge_num, sign):
    
    #model=Keras model, Edge_num=of paths to smaple as 'interesting', sign=True if train false if not
    
    tmp_list = []
    # select seeds
    print("#######debug" + str(round_cnt))
    if round_cnt == 0:
        new_seed_list = seed_list
    else:
        new_seed_list = new_seeds

    if len(new_seed_list) < edge_num: #2 X 500 random samples of seed list
        rand_seed1 = [new_seed_list[i] for i in np.random.choice(len(new_seed_list), edge_num, replace=True)]
    else:
        rand_seed1 = [new_seed_list[i] for i in np.random.choice(len(new_seed_list), edge_num, replace=False)]
    if len(new_seed_list) < edge_num:
        rand_seed2 = [seed_list[i] for i in np.random.choice(len(seed_list), edge_num, replace=True)]
    else:
        rand_seed2 = [seed_list[i] for i in np.random.choice(len(seed_list), edge_num, replace=False)]

    # function pointer for gradient computation
    fn = gen_adv2 if sign else gen_adv3

    # select output neurons to compute gradient
    interested_indice = np.random.choice(MAX_BITMAP_SIZE, edge_num)

    with open('gradient_info_p', 'w') as f:
        for idxx in range(len(interested_indice[:])):
            print("number of feature " + str(idxx))
            index = int(interested_indice[idxx])
            fl = [rand_seed1[idxx], rand_seed2[idxx]]
            adv_list = fn(index, fl, optimizer, idxx, 1, edge_num)
            tmp_list.append(adv_list)
            #Basically takes random inputs from the seed files and considers their gradient on a randomly selected
            #bitmap and returns the gradients of each input byte w.r.t output 
            for ele in adv_list:
                ele0 = [str(el) for el in ele[0]]
                ele1 = [str(int(el)) for el in ele[1]]
                ele2 = ele[2]
                f.write(",".join(ele0) + '|' + ",".join(ele1) + '|' + ele2 + "\n")


def build_model():

    optimizer= pseudoInverse(SPLIT_RATIO,C=0.001,L=0,sigma=500.0)
    if args.enable_cuda:
        optimizer.cuda()#<-Will this work?

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
    process_data()
    optimizer = build_model()
    train(optimizer)
    #100-> 200 mutation cases?
    gen_mutate2(optimizer, 100, data[:5] == b"train") #500 -> 100 in paper
    round_cnt = round_cnt + 1
    print(time.time() - t0)


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
    gen_grad(b"train")
    conn.sendall(b"start")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        else:
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

    parser.add_argument('target', nargs=argparse.REMAINDER)
    global args
    args = parser.parse_args()
    #Start program and spin up server
    setup_server()
