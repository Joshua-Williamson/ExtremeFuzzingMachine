#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import glob
import time
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
import sysv_ipc as ipc
from flow import FlowBuilder
from TorchELM import pseudoInverse 
import utils
import torch.nn.functional as F

#Setting up ip and port for internal server
HOST = '127.0.0.1'
PORT = 12012

class Edge_Data(Dataset):

    """ 
    Inherits from torch Dastasets and allows the edge information to be read into the 
    training Torch models easily. Handles data curation and processing.
    """

    def __init__(self, EFM_obj):
        self.EFM=EFM_obj
        self.seeds_list=[]
        self.nocov_list=[]
        self.vari_seed_list=[]
        self.havoc_seed_list=[]
        self.EFM.max_file_size=utils.get_max_seed_size('./seeds/')
        self.mapped_seeds=[]
        self.reduced_seeds=[]
        self.reducing_blacklist=[]
        self.bitmap = None
        self.label=np.array([])

    def __len__(self):
        return(self.EFM.corpus_size)

    def __getitem__(self,idx, grads=False):
        seed_bytes = self.vectorize_file(self.mapped_seeds[idx])
        bits = torch.as_tensor(self.bitmap[idx], dtype=torch.float32) * 2 - 1

        #Don't waste memory training 
        seed_bytes.requires_grad = True if grads else False
        return seed_bytes,bits

    def get_single_input(self,idx,grads = False):

        seed_bytes = self.vectorize_file(self.mapped_seeds[idx])
        seed_bytes = seed_bytes.reshape((1,self.EFM.max_file_size))
        #Don't waste memory training 
        seed_bytes.requires_grad = True if grads else False
        return seed_bytes

    def get_seed_index(self, seed_string):
        return self.mapped_seeds.index(seed_string)

    @utils.shm_stats(time_fmt=True)
    def process_bitmaps(self, initial = False):

        self.seeds_list=glob.glob('./seeds/*')

        if initial:
            to_map = self.seeds_list
        else:
            to_map = self.get_unmapped_seeds()


        #Go through edges of each seed reading through each output file
        for ind,seed in enumerate(to_map):
            #Are we the very first?
            first_entry = (ind == 0) * initial

            #Open our file
            with open("./edges/" + seed.split('/')[-1],'r') as seed_file:
                seed_info = seed_file.read()
                #Ignore hit counts, list of edges we've hit
                seed_edges=np.array([int(line.split(':')[0]) for line in seed_info.splitlines()])

            #List of edges for this seed that we haven't already got
            unknown_edges = np.invert(np.in1d(seed_edges,self.label))
            #Amount of zeros we'll have to append to the bitmap for the other seeds.
            pad = sum(unknown_edges)

            #If we dont have any seeds processed, we'll make an empty array in the shape of 
            #the first map
            if first_entry : self.bitmap=seed_edges
            #If not the we'll need to add some zeros to the previous seeds for the new bits
            elif initial and ind == 1: self.bitmap=np.pad(self.bitmap,[0, pad], mode='constant') 
            else : self.bitmap=np.pad(self.bitmap,[(0,0),(0, pad)], mode='constant')

            #We now know the unknown
            self.label = np.append(self.label,seed_edges[unknown_edges])
            #Add the seeds bitmap to the array
            #If were not in the initial map, just stack the array
            if not first_entry: self.bitmap = np.vstack(  ( self.bitmap, np.in1d(self.label,seed_edges).astype('int') ) )
            #Write to the emptry array

            #Update our dataset size
            self.mapped_seeds += [seed] 
            self.EFM.corpus_size += 1

            if "nocov" in seed:
                self.EFM.nocov_size += 1

        self.EFM.bitmap_size=self.bitmap.shape[1]

        return
            
    def get_unmapped_seeds(self): 
        return list(set(self.seeds_list + self.nocov_list).difference(self.mapped_seeds))
            
    def vectorize_file(self, file_name): 
        with open(file_name, 'rb') as fopen:
            btflow = torch.tensor([bt for bt in bytearray(fopen.read())], dtype=torch.float32) / 255
        # pad sequence
        if self.EFM.max_file_size > len(btflow):
            btflow = F.pad(btflow, (0, self.EFM.max_file_size -len(btflow)), 'constant', 0)
        return btflow

    @utils.shm_stats(time_fmt=True)
    def reduce_variable_files(self):

        self.vari_seed_list = glob.glob('./vari_seeds/*')
        self.havoc_seed_list = glob.glob('./havoc_seeds/*')

        time_out = 10

        for seed in (self.vari_seed_list + self.havoc_seed_list):
            if seed not in self.reducing_blacklist:
                outfile = "./seeds/"+ seed.split('/')[-1]+'min'
                bits_outfile = "./edges/"+ seed.split('/')[-1]+'min'
                success = utils.EFM_tmin(seed, outfile, bits_outfile, time_out, self.EFM.max_file_size, args.target)
                self.reducing_blacklist += [seed]

        return

    @utils.shm_stats(time_fmt=False)
    def cull_nocov(self):
        self.nocov_list=glob.glob('./nocov/*')
        cull_number = len( self.nocov_list ) + len( self.seeds_list) - args.memory_threshold

        if cull_number > 0:
            delete_mask = np.ones_like(self.bitmap,dtype = bool)
            try:
                deletes = np.random.choice( self.nocov_list, cull_number, replace=False)
            except:
                deletes = []
            for file in deletes:
                os.remove(file)
                del_index = self.mapped_seeds.index(file)
                delete_mask[del_index] = False
                self.mapped_seeds.remove(file)

            self.bitmap = self.bitmap[delete_mask]
            self.nocov_list=glob.glob('./nocov/*')
            self.EFM.corpus_size -= len(deletes)
        
        self.EFM.nocov_size = len( self.nocov_list )

        return

class Extreme_Fuzzing_Machine(utils.EFM_vars):
    
    def __init__(self, logger):
        super().__init__()
        
        self.logger = logger
        self.max_file_size=None
        self.corpus_size=0
        self.round_count=0
        self.num_grads = 150

        self.parse_executable()
        self.Data=Edge_Data(self)
        self.generate_grads(initial=True)
    
    def parse_executable(self):
        self.correspond_dict={}

        flow = FlowBuilder(args.target[0], self.logger)
        with open(flow.correspond_target, 'r') as fopen:
            self.correspond_dict = eval(fopen.readline())

    def generate_grads(self, initial=False):

        self.Data.cull_nocov()

        self.Data.process_bitmaps(initial=initial)

        optimizer = self.train()

        self.generate_mutations(optimizer, self.num_grads)

        self.round_count+=1

        return  

    def accur_1(self,y_true, y_pred):

        y_true = torch.sign(y_true - 1e-6)#Make better
        pred =torch.sign(y_pred - 1e-6) 
        summ = self.bitmap_size 
        right_num =torch.sum(torch.eq(y_true,pred),dim=1) 
        wrong_num = summ-right_num

        acc = torch.mean(right_num/(right_num+wrong_num))
        return "{:.2f}".format(acc*100)

    @utils.shm_stats(time_fmt=False)
    def train(self):

        st = time.time()
        #Build model 
        optimizer= pseudoInverse(self.corpus_size,C=0.001,L=0,sigma=500.0)
        #LoadData
        data_iter = DataLoader(self.Data, batch_size=self.corpus_size, shuffle=True)
        for _,(data,target) in enumerate(data_iter,1):
            optimizer.data=data
            optimizer.train(inputs=data, targets=target)
            output = torch.mm(optimizer.K.T,optimizer.Net)
            self.accuracy=self.accur_1(target,output)

        et = time.time()
        self.last_training = "{:.2f} sec".format(et-st)
        return optimizer

    @utils.shm_stats(time_fmt=False)
    def generate_mutations(self, optimizer, N_grads):

        interested_indices = self.select_edges(N_grads)

        with open('gradient_info_p', 'w') as f:
            for edg_idxx, seed_indxx in interested_indices:
                fl=self.Data.seeds_list[seed_indxx]
                poss, vals, fl = self.get_gradients(edg_idxx, fl, optimizer )
                
                ele0 = [str(el) for el in poss]
                ele1 = [str(int(el)) for el in vals]
                ele2 = fl
                f.write(",".join(ele0) + '|' + ",".join(ele1) + '|' + ele2 + "\n")

        return

    def get_gradients(self, selected_ind, seed, optimizer ):

        seed_ind = self.Data.get_seed_index(seed)
        x = self.Data.get_single_input(seed_ind, grads=True)
        K=optimizer.RBF_Kernel(x,optimizer.data)
        out=torch.mm(K,optimizer.Net)[:,selected_ind]
        grads_value = torch.autograd.grad(out,x)[0].numpy()
        idx = np.argsort(-np.absolute(grads_value[0]))
        val = np.sign(grads_value[0][idx])
        
        return idx, val, seed


    def select_edges(self, N_grads):
        # candidate edges
        len_seed_list = len(self.Data.seeds_list)
        if np.random.rand() < 0.1:
            # random selection mechanism
            alter_edges = np.random.choice(self.bitmap_size, N_grads)
            alter_seeds = np.random.choice(len_seed_list, N_grads).tolist()
        else:
            candidate_set = set()
            for edge in self.Data.label:
                if self.check_select_edge(edge):
                    candidate_set.add(list(self.Data.label).index(edge))
            replace_flag = True if len(candidate_set) < N_grads else False
            alter_edges = np.random.choice(list(candidate_set), N_grads, replace=replace_flag)
            alter_seeds = np.random.choice(len_seed_list, N_grads).tolist()


            #Somehow broken this? -TODO
            # for i,(seed_indx,interest_ind) in enumerate(zip(alter_seeds,alter_edges)):
            #     seed=self.Data.seeds_list[seed_indx]
            #     seed_bits=self.Data.bitmap[self.Data.get_seed_index(seed)]
            #     seed_inds=np.where(seed_bits==1)[0]
            #     if not interest_ind in list(seed_inds):
            #         candidates=list(candidate_set.intersection(seed_inds))    
            #         if candidates:
            #             alter_edges[i]=np.random.choice(candidates)
            #         else:
            #             alter_edges=np.delete(alter_edges,i)
            #             alter_seeds=np.delete(alter_seeds,i)


        interested_indice = zip(alter_edges.tolist(), alter_seeds)
        return interested_indice

    def check_select_edge(self, edge_id):
        SELECT_RATIO = 0.4
        if edge_id not in self.correspond_dict.keys():
            return True
    
        correspond_set = self.correspond_dict[edge_id]
        if len(correspond_set) == 0:
            return True

        cover_cnt = 0
        for ce in correspond_set:
            if ce in self.Data.label:
                cover_cnt += 1
        if cover_cnt / len(correspond_set) > SELECT_RATIO:
            return False
        return True
        

if __name__ == "__main__":
    
    #CLI args
    parser = utils.add_args()
    
    global args

    args = parser.parse_args()

    #If called by EFM-fuzz redirect any prints that sneak their way in
    if args.quiet:
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')


    logger=utils.init_logger('./NN_log', debug=args.quiet)

    tcp_conn = utils.connect_tcp(logger,HOST,PORT)

    utils.shm_stats.SHM_obj=utils.SHM()

    logger("Shared memory set up")

    train = tcp_conn.recv(1024)

    os.chdir(args.out_dir)

    if train[:5] !=  b'start':
        err_msg = "ERROR: efm-fuzz never ran dry"
        logger(err_msg)
        raise RuntimeError(err_msg)

    EFM=Extreme_Fuzzing_Machine(logger=logger)
    tcp_conn.sendall(b"start")

    while True:

        train = utils.wait_fuzzer_data(tcp_conn)
        
        if train:
            EFM.generate_grads()
            tcp_conn.sendall(b"start")

        EFM.Data.reduce_variable_files()
        EFM.Data.process_bitmaps(initial=False)
        EFM.Data.cull_nocov()




