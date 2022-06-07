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

#Setting up ip and port for internal server
HOST = '127.0.0.1'
PORT = 12012

class Edge_Data(Dataset):

    """ 
    Inherits from torch Dastasets and allows the edge information to be read into the 
    training Torch models easily.
    """

    def __init__(self, EFM_obj):
        self.seeds_path=glob.glob('./seeds/*')
        self.nocov_path=glob.glob('./nocov/*')
        

class EFM():
    
    def __init__(self):
        raise NotImplemented