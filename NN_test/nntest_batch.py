#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
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
from TorchELM import ELM,pseudoInverse 

#Setting up ip and port for internal server
HOST = '127.0.0.1'
PORT = 12012

#Max seed input file size allowed
MAX_FILE_SIZE = 10000
MAX_BITMAP_SIZE = 2000
round_cnt = 0
# Choose a seed for random initilzation
# seed = int(time.time())

#Fixed seed
seed = 12
np.random.seed(seed)
random.seed(seed)
seed_list = glob.glob('./seeds/*')
new_seeds = glob.glob('./seeds/id_*')
# get binary argv
argvv = sys.argv[1:]


# process training data from afl raw data
def process_data(target,arg):
    global MAX_BITMAP_SIZE
    global MAX_FILE_SIZE
    global train_len
    global test_len
    global seed_list
    global test_seed_list
    global train_seed_list

    #Max seed input file size allowed
    MAX_FILE_SIZE = 10000
    MAX_BITMAP_SIZE = 2000
    round_cnt = 0
    # Choose a seed for random initilzation
    # seed = int(time.time())

    #Fixed seed
    seed = 12
    np.random.seed(seed)
    random.seed(seed)
    # get binary argv
    argvv = sys.argv[1:]

    # shuffle training samples
    seed_list = glob.glob('./seeds/*')
    seed_list.sort()
    TTR=2./3.
    SPLIT_RATIO = int(len(seed_list)*TTR)
    np.random.shuffle(seed_list)
    train_seed_list=seed_list[:SPLIT_RATIO]
    test_seed_list=seed_list[SPLIT_RATIO:]
    train_len=len(train_seed_list)
    test_len=len(test_seed_list)
    call = subprocess.check_output

    # get MAX_FILE_SIZE
    cwd = os.getcwd()
    max_file_name = call(['ls', '-S', cwd + '/seeds/']).decode('utf8').split('\n')[0].rstrip('\n')
    MAX_FILE_SIZE = os.path.getsize(cwd + '/seeds/' + max_file_name)

    # create directories to save label, spliced seeds, variant length seeds, crashes and mutated seeds.
    os.path.isdir("./train_bitmaps/") or os.makedirs("./train_bitmaps")
    os.path.isdir("./test_bitmaps/") or os.makedirs("./test_bitmaps")
    os.path.isdir("./splice_seeds/") or os.makedirs("./splice_seeds")
    os.path.isdir("./vari_seeds/") or os.makedirs("./vari_seeds")
    os.path.isdir("./crashes/") or os.makedirs("./crashes")

    # obtain raw bitmaps
    raw_bitmap = {} #Is a dictionary for each seed file key containing the sequential ID's of each branch it covered
    tmp_cnt = [] #Hold's ID's cumlatively for each seed input
    out = ''
    for f in seed_list:
        tmp_list = [] #Keeps list of ID's for each seed file inside loop
        try:
            infile=open(f,'r')
            # append "-o tmp_file" to strip's arguments to avoid tampering tested binary.
            mem_lim= '512' if not enable_asan else 'none'
            if arg:
                if target=='./strip-new':
                    out = call(['./../afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', mem_lim, '-t', '500'] + [target,arg] + ['-o', 'tmp_file'] ,stdin=infile)
                else:
                    out = call(['./../afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', mem_lim, '-t', '500'] + [target,arg] ,stdin=infile)
            else:
                if target=='./strip-new':
                    out = call(['./../afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', mem_lim, '-t', '500'] + [target] + ['-o', 'tmp_file'] ,stdin=infile)
                else:
                    out = call(['./../afl-showmap','-q', '-e', '-o', '/dev/stdout', '-m', mem_lim, '-t', '500'] + [target] ,stdin=infile)                
            infile.close()
        except subprocess.CalledProcessError as e:
            print('Weird afl-showmap bug again') #JW DBG
            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))

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
    fit_bitmap = np.unique(bitmap, axis=1)
    print("Data dimension" + str(fit_bitmap.shape))

    trn_idx=0

    # save training data
    MAX_BITMAP_SIZE = fit_bitmap.shape[1]
    for trn_idx, i in enumerate(train_seed_list):
        file_name = "./train_bitmaps/" + i.split('/')[-1]
        np.save(file_name, fit_bitmap[trn_idx])

    for tst_idx, i in enumerate(test_seed_list):
        tst_idx=trn_idx+tst_idx
        file_name = "./test_bitmaps/" + i.split('/')[-1]
        np.save(file_name, fit_bitmap[tst_idx])


# training data generator
def generate_training_data(tt,lb, ub):
    if tt=='test':
        list=test_seed_list
        stub="./test_bitmaps/"
    elif tt=='train': 
        list=train_seed_list
        stub="./train_bitmaps/"
        
    seed = np.zeros((ub - lb, MAX_FILE_SIZE))
    bitmap = np.zeros((ub - lb, MAX_BITMAP_SIZE))
    for i in range(lb, ub):
        tmp = open(list[i], 'rb').read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
        seed[i - lb] = [j for j in bytearray(tmp)]

    for i in range(lb, ub):
        file_name = stub + list[i].split('/')[-1] + ".npy"
        bitmap[i - lb] = np.load(file_name)
    return seed, bitmap


# learning rate decay
def step_decay(epoch):
    initial_lrate = 0.001
    drop = 0.7
    epochs_drop = 10.0
    lrate = initial_lrate * math.pow(drop, math.floor((1 + epoch) / epochs_drop))
    return lrate

def train_generate(tt,batch_size):

    # load a batch of training data
    if tt=='train':
        SPLIT_RATIO=train_len
    if tt=='test':
        SPLIT_RATIO=test_len

    for i in range(0, SPLIT_RATIO, batch_size):
        # load full batch if batchsize is greater than the seeds availible
        if (i + batch_size) > SPLIT_RATIO:
            x, y = generate_training_data(tt,i, SPLIT_RATIO)
            x = x.astype('float32') / 255
        # load remaining data for last batch
        else:
            x, y = generate_training_data(tt,i, i + batch_size)
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
        print(f_diff, l_diff)
        randd = random.choice(seed_list)

def build_model():
    #Fixed batch size and epoch?
    batch_size = 32
    num_classes = MAX_BITMAP_SIZE #Remember that this is called every iteration such that is 
    epochs = 50                   #retrained on new bitmap sizes.

    model = ELM(input_size=MAX_FILE_SIZE,output_size=num_classes,hidden_size=4096,activation='relu')
    if enable_cuda:
        model.cuda()

    optimizer= pseudoInverse(params=model.parameters(),C=0.001,L=0)

    return model,optimizer

def accur_1(y_true, y_pred):
    y_true = torch.round(y_true)
    pred =torch.round(y_pred) 
    summ = MAX_BITMAP_SIZE
    right_num =torch.sum(torch.eq(y_true,pred),dim=1) 
    wrong_num = summ-right_num
    return torch.mean(right_num/(right_num+wrong_num))

def train(model,optimizer):
    batch_size=16
    init = time.time()
    model.train()
    for batch_idx, (data, target) in enumerate(train_generate(tt='train',batch_size=batch_size)):
        if enable_cuda:
            data, target = data.cuda(), target.cuda()
        data, target = Variable(data,requires_grad=True, volatile=False), \
                       Variable(target.type(torch.float32),requires_grad=True, volatile=False)
        hiddenOut = model.forwardToHidden(data)
        optimizer.train(inputs=hiddenOut, targets=target)
        output = model.forward(data)
        pred=output
        acc=accur_1(target,pred)

    ending = time.time()
    print('Training time: {:.2f}sec/ Training Accuracy: {:.2f}'.format(ending - init,acc))
    return acc, ending-init

def test(model):
    batch_size=len(test_seed_list)
    init = time.time()
    model.train()
    for batch_idx, (data, target) in enumerate(train_generate(tt='test',batch_size=batch_size)):
        if enable_cuda:
            data, target = data.cuda(), target.cuda()
        data, target = Variable(data,requires_grad=True, volatile=False), \
                       Variable(target.type(torch.float32),requires_grad=True, volatile=False)
        output = model.forward(data)
        pred=output
        acc=accur_1(target,pred)

    ending = time.time()
    print('Testing time: {:.2f}sec/ Testing Accuracy: {:.2f}'.format(ending - init, acc))
    return acc


def gen_grad(target,arg):
    global round_cnt
    t0 = time.time()
    process_data(target,arg)
    print("Bitmap generating time: {:.2f}".format(time.time()-t0))
    model,optimiser = build_model()
    acc,train_time=train(model,optimiser)
    val_acc=test(model)
    print("Total pre-process time: {:.2f}".format(time.time() - t0))
    return acc,val_acc,train_time


if __name__ == '__main__':
    prog_dir={'harfbuzz':{'target':'./hb-fuzzer','arg':None},
              'libjpeg':{'target':'./djpeg','arg':None},
              'libxml':{'target':'./xmllint','arg':None},
              'mupdf':{'target':'./mutool','arg':'show'},
              'nm':{'target':'./nm-new','arg':'-C'},
              'objdump':{'target':'./objdump','arg':'-D'},
              'readelf':{'target':'./readelf','arg':'-a'},
              'size':{'target':'./size','arg':None},
              'strip':{'target':'./strip-new','arg':None},
              'zlib':{'target':'./miniunz','arg':'-o'}
               }

    results_dir={'harfbuzz':{},
              'libjpeg':{},
              'libxml':{},
              'mupdf':{},
              'nm':{},
              'objdump':{},
              'readelf':{},
              'size':{},
              'strip':{},
              'zlib':{}}
    global enable_cuda
    enable_asan=False 
    enable_cuda=False
    prog_dirs=os.listdir('.')
    for prog,bin in zip(prog_dir.keys(),prog_dir.values()):
        print("Program: "+ prog)
        os.chdir(prog)
        target=bin['target']
        arg=bin['arg']
        acc,val_acc,train_time=gen_grad(target,arg)
        results_dir[prog]['accuracy']=acc.item()
        results_dir[prog]['validation accuracy']=val_acc.item()
        results_dir[prog]['train time']=train_time
        os.chdir('..')
        
    with open('ELM_results.json','w') as fp:
        json.dump(results_dir,fp, indent=4) 