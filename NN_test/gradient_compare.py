import argparse
import os
import sys
import glob
import math
import time
import keras
import random
import socket
import subprocess
import numpy as np
import tensorflow as tf
import keras.backend as K
from collections import Counter
from tensorflow import set_random_seed
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
from keras.callbacks import ModelCheckpoint

def build_model():
    #Fixed batch size and epoch?
    batch_size = 32
    num_classes = MAX_BITMAP_SIZE #Remember that this is called every iteration such that is 
    epochs = 50                   #retrained on new bitmap sizes.

    #Two FC layers with 
    #MAX_FILE_SIZE -> FC -> 4096 -> RELU -> FC -> MAX_BITMAP_SIZE -> SIGMOID
    model = Sequential()
    model.add(Dense(4096, input_dim=MAX_FILE_SIZE))
    model.add(Activation('relu'))
    model.add(Dense(num_classes))
    model.add(Activation('sigmoid'))

    #Adams
    opt = keras.optimizers.adam(lr=0.0001) #Fixed LR

    model.compile(loss='binary_crossentropy', optimizer=opt )
    model.summary()

    return model

# compute gradient for given input
# taking gradient of randomly selected bitmap output at randomly selected input
def gen_adv2(f, fl, model, layer_list, idxx, splice):
    adv_list = []
    loss = layer_list[-2][1].output[:, f]   #Takes the output of the f entry of the bitmap classifaction. Of second dense layer...
    grads = K.gradients(loss, model.input)[0]   #Takes gradient of loss w.r.t all NN input params.
    iterate = K.function([model.input], [loss, grads])
    x = vectorize_file(fl)
    loss_value, grads_value = iterate([x])
    idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
    val = np.sign(grads_value[0][idx])
    adv_list.append((idx, val, fl))
    return adv_list

# get vector representation of input
def vectorize_file(fl):
    seed = np.zeros((1, MAX_FILE_SIZE))
    tmp = open(fl, 'rb').read()
    ln = len(tmp)
    if ln < MAX_FILE_SIZE:
        tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
    seed[0] = [j for j in bytearray(tmp)]
    seed = seed.astype('float32') / 255
    return seed

with open('gradient_testing_info_neuzz','w') as g:
    with open('gradient_testing_info_ELM') as f:
        i=0
        for line in f:
            if i == 0:
                global MAX_FILE_SIZE
                global MAX_BITMAP_SIZE
                MAX_FILE_SIZE,MAX_BITMAP_SIZE = line.split("|")
                MAX_FILE_SIZE,MAX_BITMAP_SIZE = int(MAX_FILE_SIZE), int(MAX_BITMAP_SIZE) 
                model = build_model()
                model.load_weights('hard_label.h5')
                layer_list = [(layer.name, layer) for layer in model.layers]
                i+=1
            else:
                if i % 100 == 0:
                    del model
                    K.clear_session()
                    model = build_model()
                    model.load_weights('hard_label.h5')
                    layer_list = [(layer.name, layer) for layer in model.layers]
        
                pos,val,file,output=line.split("|")
                output=int(output)

                adv_list = gen_adv2(output, file, model, layer_list, i, 1)

                for ele in adv_list:
                    ele0 = [str(el) for el in ele[0]]
                    ele1 = [str(int(el)) for el in ele[1]]
                    ele2 = ele[2]
                    g.write(",".join(ele0) + '|' + ",".join(ele1) + '|' + ele2 + '|' + str(output)+ "\n")
                i+=1