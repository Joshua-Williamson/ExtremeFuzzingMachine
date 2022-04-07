#Forked form @chickenbestlover & modified

import torch
import torch.utils.data.dataloader
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torchvision import datasets, transforms
from torch.autograd import Variable
import time

class pseudoInverse(object):
    def __init__(self,input_dim,C=1e-2,forgettingfactor=1,L =100,is_cuda=False,sigma=0.0001):
        self.sigma=sigma
        self.is_cuda=is_cuda
        self.C=C
        self.L=L
        self.forgettingfactor=forgettingfactor
        self.dimInput=input_dim
        self.M=Variable(torch.inverse(self.C*torch.eye(self.dimInput)),requires_grad=True, volatile=False)

        if self.is_cuda:
            self.M=self.M.cuda()
        
    def pseudoBig(self,inputs,oneHotTarget):
        xtx =inputs 
        dimInput=inputs.size()[1]
        I = Variable(torch.eye(dimInput),requires_grad=True, volatile=False)
        if self.is_cuda:
            I = I.cuda()
        if self.L > 0.0:
            mu = torch.mean(inputs, dim=0, keepdim=True)  # [ 1 * n_features ]
            S = inputs - mu
            S = torch.mm(S.t(), S)
            self.M = Variable(torch.inverse(xtx.data + self.C * (I.data+self.L*S.data)),requires_grad=True, volatile=False)
        else:
            self.M = Variable(torch.inverse(xtx.data + self.C *I.data), requires_grad=True, volatile=False)

        w = torch.mm(self.M, oneHotTarget)
        return w

    def pseudoSmall(self,inputs,oneHotTarget):
        xxt = inputs 
        numSamples=inputs.size()[0]
        I = Variable(torch.eye(numSamples),requires_grad=True, volatile=False)
        if self.is_cuda:
            I = I.cuda()
        self.M = Variable(torch.inverse(xxt.data + self.C * I.data),requires_grad=True, volatile=False)
        w = torch.mm(self.M, oneHotTarget)
        return w

    def train(self,inputs,targets):
        targets = targets.view(targets.size(0),-1)
        numSamples=inputs.size()[0]
        dimInput=inputs.size()[1]
        self.K=self.RBF_Kernel(inputs,inputs)

        if numSamples>dimInput:
            self.Net = self.pseudoBig(self.K,targets)
        else:
            self.Net = self.pseudoSmall(self.K,targets)

    # def RBF_Kernel(self,x,y,sigma):
    #     K = torch.zeros(len(x),len(y))
    #     for i,ii in enumerate(x):
    #         for j, jj in enumerate(y):
    #             sum=ii-jj
    #             sum=torch.dot(sum,sum)
    #             K[i,j]=torch.exp(-sum/(2*sigma**2))

    #     return K 
    def RBF_Kernel(self,x,y): 
        # t0=time.time()
        gamma = 1/(2*self.sigma**2)
        sum=torch.cdist(x,y,p=2)**2 
        K = torch.exp(-gamma * sum)
        # t1=time.time()
        # print('Cdist time:' + str(t1-t0))

        # K = torch.zeros(len(x),len(y))
        # for i,ii in enumerate(x):
        #     for j, jj in enumerate(y):
        #         sum=ii-jj
        #         sum=torch.dot(sum,sum)
        #         K[i,j]=torch.exp(-sum/(2*self.sigma**2))
        # print('Shit version:'+ str(time.time()-t1)) 
        return K
