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
    adv_list.append((idx, val, fl,loss_value))
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

def train_generate(batch_size):
    while 1:
        for i in range(0, train_len, batch_size):
            # load full batch if batchsize is greater than the seeds availible
            if (i + batch_size) > train_len:
                x, y = generate_training_data(i, train_len)
                x = x.astype('float32') / 255
            # load remaining data for last batch
            else:
                x, y = generate_training_data(i, i + batch_size)
                x = x.astype('float32') / 255
            yield (x,y)

def generate_training_data(lb, ub):
        
    seed = np.zeros((ub - lb, MAX_FILE_SIZE))
    bitmap = np.zeros((ub - lb, MAX_BITMAP_SIZE))
    for i in range(lb, ub):
        tmp = open(train_seed_list[i], 'rb').read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
        seed[i - lb] = [j for j in bytearray(tmp)]

    for i in range(lb, ub):
        file_name = "./train_bitmaps/" + train_seed_list[i].split('/')[-1] + ".npy"
        bitmap[i - lb] = np.load(file_name)
    return seed, bitmap


def train(model):
    st=time.time()
    loss_history = LossHistory()
    lrate = keras.callbacks.LearningRateScheduler(step_decay)
    callbacks_list = [loss_history, lrate]
    hist=model.fit_generator(train_generate(16), #BS of 16, fixed?
                        steps_per_epoch=(train_len / 16 + 1),
                        epochs=50,
                        verbose=1, callbacks=callbacks_list)
    # Save model and weights
    model.save_weights("hard_label.h5")
    #plot_acc(hist)
    ft=time.time()-st
    print("Finished training in: {:.2f}".format(ft))

class LossHistory(keras.callbacks.Callback):

    def on_train_begin(self, logs={}):
        self.losses = []
        self.lr = []

    def on_epoch_end(self, batch, logs={}):
        self.losses.append(logs.get('loss'))
        self.lr.append(step_decay(len(self.losses)))
        print(step_decay(len(self.losses)))


# learning rate decay
def step_decay(epoch):
    initial_lrate = 0.001
    drop = 0.7
    epochs_drop = 10.0
    lrate = initial_lrate * math.pow(drop, math.floor((1 + epoch) / epochs_drop))
    return lrate

if __name__ == "__main__":
    global train_len
    global train_seed_list
    train_seed_list = glob.glob('./seeds/*')
    train_len=len(train_seed_list)
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
                    # train(model)
                    model.load_weights('hard_label.h5')#<-uncomment if already done
                    layer_list = [(layer.name, layer) for layer in model.layers]
                    i+=1
                    g.write(str(MAX_FILE_SIZE)+"|"+str(MAX_BITMAP_SIZE) + "\n")
                else:
                    if i % 100 == 0:
                        del model
                        K.clear_session()
                        model = build_model()
                        model.load_weights('hard_label.h5')
                        layer_list = [(layer.name, layer) for layer in model.layers]
        
                    pos,val,file,_,output=line.split("|")
                    output=int(output)

                    adv_list = gen_adv2(output, file, model, layer_list, i, 1)

                    for ele in adv_list:
                        ele0 = [str(el) for el in ele[0]]#pos
                        ele1 = [str(int(el)) for el in ele[1]]#val
                        ele2 = ele[2]#file
                        ele3 = str(ele[3])#output for debug
                        g.write(",".join(ele0) + '|' + ",".join(ele1) + '|' + ele2 + '|' +ele3 + '|' + str(output)+ "\n")

                    i+=1