import pycrypto

import socket
import sys
import csv
import math
import time
import numpy as np
import fileTransfer
from decimal import *

##########################################################
##########################################################
##########################################################

regSel = 3

regAlg = ""
MAXVALUE              = 0
PRECISION             = 0
PRECISIONDECIMALSIZE  = 0
PRECISIONDECIMALSIZEX = 0
ENTRYSIZE             = 0
CYCLOTOMICM           = 0
PLAINTEXTPRIMESIZE    = 0
PLAINTEXTBITSIZE      = 0
REGRLOOPCOUNT         = 0
DCRTBITSIZE           = 0
DCRTPRIMESIZE         = 0
NUMTHREADS            = 0


if regSel == 1:
    regAlg = "NORMAL"
elif regSel == 2: 
    regAlg = "LOGISTIC"
elif regSel == 3:
    regAlg = "POISSON"

if regAlg == "NORMAL":
    MAXVALUE              = 10
    PRECISION             = 10
    PRECISIONDECIMALSIZE  = 10
    PRECISIONDECIMALSIZEX = 2

    PLAINTEXTPRIMESIZE    = 6
    PLAINTEXTBITSIZE      = 20

    REGRLOOPCOUNT         = 2

    NUMTHREADS            = 1
elif regAlg == "LOGISTIC":
    MAXVALUE              = 10
    PRECISION             = 10
    PRECISIONDECIMALSIZE  = 12
    PRECISIONDECIMALSIZEX = 1

    PLAINTEXTPRIMESIZE    = 5
    PLAINTEXTBITSIZE      = 20

    REGRLOOPCOUNT         = 10

    NUMTHREADS            = 1
elif regAlg == "POISSON":
    MAXVALUE              = 10
    PRECISION             = 10
    PRECISIONDECIMALSIZE  = 10 
    PRECISIONDECIMALSIZEX = 2

    PLAINTEXTPRIMESIZE    = 5
    PLAINTEXTBITSIZE      = 20

    REGRLOOPCOUNT         = 2

    NUMTHREADS            = 8
    
GlmParamList = [ MAXVALUE, PRECISION, PRECISIONDECIMALSIZE, PRECISIONDECIMALSIZEX,
                PLAINTEXTPRIMESIZE, PLAINTEXTBITSIZE, REGRLOOPCOUNT, NUMTHREADS]
                
realResults = [ [3.6745554551111108,  0.7842383988522375,  1.2302013919502843,  -1.5370575140827381,   -2.7313786051999478],
                [7.0926111620630845,  1.2856318959144208,  2.0123455188618156,  -2.7444339290424296,   -4.4630534104986532],
               [11.6168341053094544,  1.7605746013985570,  2.6966126939506729,  -4.0099278137242864,   -6.4006471598762067],
               [17.4836381822625242,  2.1702776864656022,  3.3915788865117493,  -5.3289901598043423,   -8.7297167642808127],
               [24.7648844307089497,  2.4186021611981134,  4.2573784030876114,  -6.6639385605183010,  -11.5205744217603474],
               [32.8993566691660675,  2.4837084671409579,  5.3488496262603480,  -7.9547607376625482,  -14.6406404624534616],
               [39.6818742698817601,  2.4699968009764612,  6.2959234364872563,  -8.9770188244821387,  -17.2187100065102641],
               [42.3698402994337755,  2.4648029154944382,  6.6489997880444482,  -9.3868214488516681,  -18.1954763651185125],
               [42.6355733455598482,  2.4652061276013080,  6.6806493557471898,  -9.4290109005654337,  -18.2854464630521498],
               [42.6378036527676798,  2.4652201932619415,  6.6808869990902311,  -9.4293851253192376,  -18.2861368433573190]]

keyDir                  = "demoData/python/glm/client/keyDir"
keyfileName             = "keyFileLinReg"
ciphertextDataDir       = "demoData/python/glm/client/ciphertextDataDir"
ciphertextDataFileName  = "Vertical_Artifical_Data"
plaintextDataDir        = "demoData/python/glm/client/plaintextDataDir"
plaintextDataFileName   = "case3_poisson.csv"

ciphertextXFileName    = "ciphertext-x"
ciphertextYFileName    = "ciphertext-y"
ciphertextWFileName    = "ciphertext-w"

ciphertextXWFileName   = "ciphertext-xw"

ciphertextMUFileName    = "ciphertext-mu"
ciphertextSFileName     = "ciphertext-S"
ciphertextC1FileName    = "ciphertext-C1"
ciphertextC2FileName    = "ciphertext-C2"
ciphertextC1C2FileName  = "ciphertext-C1C2"

pathList = [keyDir, keyfileName, ciphertextDataDir, ciphertextDataFileName, plaintextDataDir, plaintextDataFileName,
            ciphertextXFileName, ciphertextYFileName, ciphertextWFileName, ciphertextXWFileName, ciphertextMUFileName,
            ciphertextSFileName, ciphertextC1FileName, ciphertextC2FileName, ciphertextC1C2FileName]


regResultList = [[0 for x in range(5)] for y in range(REGRLOOPCOUNT)] 

timing = {"Keygen":0.0, "Encrypt":0.0, "SendParam":0.0, "SendKeyCrypt":0.0,
          "SendXY":0.0, "SendW":0.0, "RecvXW":0.0, "ComputeStep1":0.0, "SendMuS":0.0,
          "RecvC1":0.0, "ComputeStep2":0.0, "SendC1":0.0, "RecvC1":0.0, "ComputeStep3":0.0}

##########################################################
##########################################################
##########################################################
totalTime0 = time.time()
glm = pycrypto.GLMClient()

glm.SetFileNamesPaths(pathList)
glm.SetGLMParams(GlmParamList)

t0 = time.time()
glm.KeyGen()
t1 = time.time()
timing["Keygen"] = timing["Keygen"] + (t1-t0)

t0 = time.time()
glm.Encrypt()
t1 = time.time()
timing["Encrypt"] = timing["Encrypt"] + (t1-t0)

glm.SetGLMContext()

##########################################################
##########################################################
##########################################################
## Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

## Connect the socket to the port where the server is listening
server_address = ('localhost', 1516)
print >>sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)

##########################################################
##########################################################
##########################################################
#Send Parameters
print '\nSend:   Parameters...',
t0 = time.time()
paramSize = str(len(GlmParamList))
paramSize = fileTransfer.padding(paramSize)
sock.send(paramSize)
fileTransfer.waitAck(sock)
for i in range(len(GlmParamList)):
    paramSTR = str(GlmParamList[i])
    paramSTR = fileTransfer.padding(paramSTR)
    sock.send(paramSTR)
    fileTransfer.waitAck(sock)
t1 = time.time()
timing["SendParam"] = timing["SendParam"] + (t1-t0)
print 'Completed'

##########################################################

print 'Send:   Key and CryptoContext...',
t0 = time.time()
for i in range(PLAINTEXTPRIMESIZE):
    
    pubKeyPath = keyDir+"/"+keyfileName+"-public" + str(i) + ".txt"
    fileTransfer.sendFile(pubKeyPath, sock)

    evalKeyMultPath = keyDir+"/"+keyfileName+"-eval-mult" + str(i) + ".txt"
    fileTransfer.sendFile(evalKeyMultPath, sock)
    
    evalKeySumPath  = keyDir+"/"+keyfileName+"-eval-sum" + str(i) + ".txt"
    fileTransfer.sendFile(evalKeySumPath, sock)
    
    cryptoContPath  = keyDir+"/"+keyfileName+"-cryptocontext" + str(i) + ".txt"
    fileTransfer.sendFile(cryptoContPath, sock)
                                                             
t1 = time.time()
print 'Completed'    
timing["SendKeyCrypt"] = timing["SendKeyCrypt"] + (t1-t0)
                                                         
##########################################################

# Send data
print 'Send:   X and Y...',
t0 = time.time()
for i in range(PLAINTEXTPRIMESIZE):
            
    ciphertextXPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextXFileName+"-" + str(i) + ".txt"
    fileTransfer.sendFile(ciphertextXPath, sock)
        
    ciphertextYPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextYFileName+"-" + str(i) + ".txt"
    fileTransfer.sendFile(ciphertextYPath, sock)
    
t1 = time.time()
timing["SendXY"] = timing["SendXY"] + (t1-t0)    
print 'Completed'

##########################################################
    
for loop in range(REGRLOOPCOUNT):
    
    print '\n'
    print '########################################################'
    print '         Iteration ', loop
    print '########################################################'

    totaltimestart = time.time()
    print 'Send:   W...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):
    
        ciphertextWPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextWFileName+"-" + str(i) + ".txt"
        fileTransfer.sendFile(ciphertextWPath, sock)
    
    t1 = time.time()
    timing["SendW"] = timing["SendW"] + (t1-t0)    
    print 'Completed'

    ##########################################################
    
    print 'Recv:   X*W...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):

        ciphertextXWPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextXWFileName+"-" + str(i) + ".txt"
        fileTransfer.recieveFile(ciphertextXWPath, sock)
    
    t1 = time.time()
    timing["RecvXW"] = timing["RecvXW"] + (t1-t0) 
    print 'Completed'
    
    ##########################################################
    
    print 'Comp:   Link Function (Step-1)...',    
    t0 = time.time()
    glm.Step1ComputeLink(regAlg)
    t1 = time.time()
    timing["ComputeStep1"] = timing["ComputeStep1"] + (t1-t0)     
    print 'Completed'
    
    ##########################################################

    # Send data
    print 'Send:   Mu and S...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):
        
        ciphertextMUPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextMUFileName+"-"+ str(i) + ".txt"
        fileTransfer.sendFile(ciphertextMUPath, sock)
        
        ciphertextSPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextSFileName+"-"+ str(i) + ".txt"
        fileTransfer.sendFile(ciphertextSPath, sock)
        
    t1 = time.time()
    timing["SendMuS"] = timing["SendMuS"] + (t1-t0) 
    print 'Completed'
    
    ##########################################################
    
    print 'Recv:   C1=X^T*S*X...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):
               
        ciphertextC1Path = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextC1FileName+"-" + str(i) + ".txt"
        fileTransfer.recieveFile(ciphertextC1Path, sock)
 
    t1 = time.time()
    timing["RecvC1"] = timing["RecvC1"] + (t1-t0)     
    print 'Completed'
    
    ##########################################################
    
    print 'Comp:   C1^{-1}=(X^T*S*X)^{-1} (Step-2)...',
    t0 = time.time()
    glm.Step2RescaleC1()
    
    t1 = time.time()
    timing["ComputeStep2"] = timing["ComputeStep2"] + (t1-t0)     
    print 'Completed'

    ##########################################################

    print 'Send:   C1^{-1}=(X^T*S*X)^{-1}...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):

        ciphertextC1Path = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextC1FileName+"-" + str(i) + ".txt"
        fileTransfer.sendFile(ciphertextC1Path, sock)
            
    t1 = time.time()
    timing["SendC1"] = timing["SendC1"] + (t1-t0)     
    print 'Completed'
    
    ##########################################################
    
    print 'Recv:   w + C1^{-1}*C2 = w + (X^T*S*X)^{-1}*X^T*(y-mu)...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):
    
        ciphertextC1C2Path = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextC1C2FileName+"-" + str(i) + ".txt"
        fileTransfer.recieveFile(ciphertextC1C2Path, sock)

    t1 = time.time()
    timing["RecvC1"] = timing["RecvC1"] + (t1-t0)  
    print 'Completed'   
    
    ##########################################################
    
    print 'Rescale:w + (X^T*S*X)^{-1}*X^T*(y-mu)...',
    t0 = time.time()
    regResults = glm.Step3RescaleRegressor()
    t1 = time.time()
    timing["ComputeStep3"] = timing["ComputeStep3"] + (t1-t0)     
    print 'Completed' 

    ##########################################################
    t0 = time.time()
    print 'Error:', glm.ComputeError()
    t1 = time.time()
    print 'Error timing:\t', (t1-t0)     
    ##########################################################
    totaltimefinish = time.time()
    print '\n',
    print '################################'
    print '   Results for w - Iteration ', loop
    print '################################'  
    print 'Comp:', regResults
    # If the input data is fishData.csv display the real result
    if plaintextDataFileName == "fishData.csv":
        print 'Real:', realResults[loop]
    print '################################'
    
    regResultList[loop] = regResults
    
    print 'Time for Loop', loop,':', (totaltimefinish-totaltimestart)

sock.close()

##########################################################
##########################################################
##########################################################

print '\n'
print '################################'
print '   Results  of w '
print '################################'  
for i in range(len(regResultList)):
    print 'Iter -', i,'   ',
    
    for j in range(len(regResultList[i])):
        print "%.6f   " % (regResultList[i][j]),
        
    print '\n',
    
##########################################################
##########################################################
##########################################################
'''
print timing

l = [i for i in timing.items()]
for i in range(len(l)):
    print l[i][0], '\t', l[i][1]

totalTime1 = time.time()
print 'Total time\t', totalTime1-totalTime0
'''
##########################################################
##########################################################
##########################################################

print '\n'
print '################################'
print '   Timings '
print '################################'
print "Keygen:         ", timing["Keygen"]
print "Encrypt:        ", timing["Encrypt"]

print "SendParam:      ", timing["SendParam"]
print "SendKeyCrypt:   ", timing["SendKeyCrypt"]
print "SendXY:         ", timing["SendXY"]

print "SendW:          ", timing["SendW"]

print "ComputeStep1:   ", timing["ComputeStep1"]
print "SendMuS:        ", timing["SendMuS"]

print "ComputeStep2:   ", timing["ComputeStep2"]
print "SendC1:         ", timing["SendC1"]

print "ComputeStep3:   ", timing["ComputeStep3"]


glm.PrintTimings()

























