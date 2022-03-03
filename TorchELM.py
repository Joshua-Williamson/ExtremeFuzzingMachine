#Forked form @chickenbestlover & modified

import torch
import torch.utils.data.dataloader
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torchvision import datasets, transforms
from torch.autograd import Variable
import time

class ELM(nn.Module):
    def __init__(self,input_size,output_size,hidden_size=4096,activation='leaky_relu'):
        super(ELM, self).__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.activation = getattr(F,activation)
        if activation in ['relu', 'leaky_relu']:
            torch.nn.init.xavier_uniform_(self.fc1.weight,gain=nn.init.calculate_gain(activation))
        else:
            torch.nn.init.xavier_uniform_(self.fc1.weight, gain=1)
        self.fc2 = nn.Linear(hidden_size, output_size, bias=False) # ELM do not use bias in the output layer.
        self.sig =  nn.Sigmoid()


    def forward(self, x):
        x = x.view(x.size(0),-1)
        x = self.fc1(x)
        x = self.activation(x)
        x = self.fc2(x)
        x = self.sig(x)
        return x

    def forward_to_sig(self, x):
        x = x.view(x.size(0),-1)
        x = self.fc1(x)
        x = self.activation(x)
        x = self.fc2(x)
        return x

    def forwardToHidden(self, x):
        x = x.view(x.size(0),-1)
        x = self.fc1(x)
        x = self.activation(x)
        return x


class pseudoInverse(object):
    def __init__(self,params,C=1e-2,forgettingfactor=1,L =100):
        self.params=list(params)
        self.is_cuda=self.params[len(self.params)-1].is_cuda
        self.C=C
        self.L=L
        self.w=self.params[len(self.params)-1]
        self.w.data.fill_(0) #initialize output weight as zeros
        # For sequential learning in OS-ELM
        self.dimInput=self.params[len(self.params)-1].data.size()[1]
        self.forgettingfactor=forgettingfactor
        self.M=Variable(torch.inverse(self.C*torch.eye(self.dimInput)),requires_grad=True, volatile=False)

        if self.is_cuda:
            self.M=self.M.cuda()

    def initialize(self):
        self.M = Variable(torch.inverse(self.C * torch.eye(self.dimInput)),requires_grad=True, volatile=False)

        if self.is_cuda:
            self.M = self.M.cuda()
        self.w = self.params[len(self.params) - 1]
        self.w.data.fill_(0.0)

    def pseudoBig(self,inputs,oneHotTarget):
        xtx = torch.mm(inputs.t(), inputs) # [ n_features * n_features ]
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

        w = torch.mm(self.M, inputs.t())
        w = torch.mm(w, oneHotTarget)
        self.w.data = w.t().data

    def pseudoSmall(self,inputs,oneHotTarget):
        xxt = torch.mm(inputs, inputs.t())
        numSamples=inputs.size()[0]
        I = Variable(torch.eye(numSamples),requires_grad=True, volatile=False)
        if self.is_cuda:
            I = I.cuda()
        self.M = Variable(torch.inverse(xxt.data + self.C * I.data),requires_grad=True, volatile=False)
        w = torch.mm(inputs.t(), self.M)
        w = torch.mm(w, oneHotTarget)

        self.w.data = w.t().data

    def train(self,inputs,targets, oneHotVectorize=True):
        targets = targets.view(targets.size(0),-1)
        if oneHotVectorize:
            targets=self.oneHotVectorize(targets=targets)
        numSamples=inputs.size()[0]
        dimInput=inputs.size()[1]
        dimTarget=targets.size()[1]

        if numSamples>dimInput:
            self.pseudoBig(inputs,targets)
        else:
            self.pseudoSmall(inputs,targets)



    def train_sequential(self,inputs,targets):
        oneHotTarget = self.oneHotVectorize(targets=targets)
        numSamples = inputs.size()[0]
        dimInput = inputs.size()[1]
        dimTarget = oneHotTarget.size()[1]

        if numSamples<dimInput:
            I1 = Variable(torch.eye(dimInput))
            if self.is_cuda:
                I1 = I1.cuda()
            xtx=torch.mm(inputs.t(),inputs)
            self.M=Variable(torch.inverse(xtx.data+self.C*I1.data),requires_grad=True, volatile=False)

        I = Variable(torch.eye(numSamples))
        if self.is_cuda:
            I = I.cuda()

        self.M = (1/self.forgettingfactor) * self.M - torch.mm((1/self.forgettingfactor) * self.M,
                                             torch.mm(inputs.t(), torch.mm(Variable(torch.inverse(I.data + torch.mm(inputs, torch.mm((1/self.forgettingfactor)* self.M, inputs.t())).data),requires_grad=True, volatile=False),
                                             torch.mm(inputs, (1/self.forgettingfactor)* self.M))))


        self.w.data += torch.mm(self.M,torch.mm(inputs.t(),oneHotTarget - torch.mm(inputs,self.w.t()))).t().data


    def oneHotVectorize(self,targets):
        oneHotTarget=torch.zeros(targets.size()[0],int(targets.max().item())+1)

        for i in range(targets.size()[0]):
            oneHotTarget[i][int(targets[i].item())]=1

        if self.is_cuda:
            oneHotTarget=oneHotTarget.cuda()
        oneHotTarget=Variable(oneHotTarget,requires_grad=True, volatile=False)

        return oneHotTarget
