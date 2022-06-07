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
from torch.autograd import Variable
import torch
from torch.utils.data import Dataset 
import sysv_ipc as ipc
from flow import FlowBuilder
from TorchELM import pseudoInverse 
import utils

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
        self.seeds_path=glob.glob('./seeds/*')
        self.nocov_path=glob.glob('./nocov/*')

    def __len__(self):
        pass

    def __getitem__(self):
        pass

    def process_bitmaps

class Extreme_Fuzzing_Machine():
    
    #Setters and properties to update the stats
    #Not that important, ignore till the :)
    @property
    def accuracy(self):
        return self._accuracy

    @utils.shm_stats
    @accuracy.setter
    def accuracy(self, value):
        self._accuracy=value
        return value

    @property
    def bitmap_size(self):
        return self._bitmap_size

    @utils.shm_stats
    @bitmap_size.setter
    def bitmap_size(self, value):
        self._bitmap_size=value
        return value

    @property
    def corpus_size(self):
        return self._corpus_size

    @utils.shm_stats
    @corpus_size.setter
    def corpus_size(self, value):
        self._corpus_size=value
        return value

    @property
    def last_mapping(self):
        return self._last_mapping

    @utils.shm_stats
    @last_mapping.setter
    def last_mapping(self, value):
        self._last_mapping=value
        return value

    @property
    def last_training(self):
        return self._last_training

    @utils.shm_stats
    @last_training.setter
    def last_training(self, value):
        self._last_training=value
        return value

    @property
    def num_grads(self):
        return self._num_grads

    @utils.shm_stats
    @num_grads.setter
    def num_grads(self, value):
        self._num_grads=value
        return value
    
    #:)

    def __init__(self):
        self._accuracy=None
        self._bitmap_size=None
        self._corpus_size=None
        self._last_mapping=None
        self._last_training=None
        self._num_grads=None

if __name__ == "__main__":
    EFM=Extreme_Fuzzing_Machine()
    utils.shm_stats.SHM_obj=EFM
