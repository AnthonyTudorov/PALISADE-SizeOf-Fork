#import /home/dante/github/palisade-student-edition/bin/lib/pycrypto

import socket
import sys
import time

import pycrypto

import fileTransfer
import numpy as np
from urllib import localhost


keyDir                  = "demoData/python/glm/server/keyDir"
keyfileName             = "keyFileLinReg"
ciphertextDataDir       = "demoData/python/glm/server/ciphertextDataDir"
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



timing = {"RecvParam":0.0, "RecvKeyCrypt":0.0, "RecvXY":0.0, "RecvW":0.0, "ComputeStep1":0.0, 
          "SendXW":0.0, "RecvMuS":0.0, "SendXTSX":0.0, "ComputeStep2":0.0, "SendC1":0.0, 
          "RecvC1":0.0, "ComputeStep3":0.0, "SendC1-2":0.0}

GlmParamList = []

glm = pycrypto.GLMServer()

glm.SetFileNamesPaths(pathList)
##########################################################
##########################################################
##########################################################

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 1212)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

# Wait for a connection
print >>sys.stderr, 'waiting for a connection'
sock, client_address = sock.accept()
#comment
print >>sys.stderr, 'connection from', client_address

##########################################################
##########################################################
##########################################################
print '\nRecv:   Parameters...',
t0 = time.time()
paramSize = sock.recv(32)
fileTransfer.sendAck(sock)
paramSize = fileTransfer.clearPadding(paramSize)
paramSize = int(paramSize)
GlmParamList = [0.0 for x in range(paramSize)]
for i in range(paramSize):
    paramSTR = sock.recv(32)
    fileTransfer.sendAck(sock)
    paramSTR = fileTransfer.clearPadding(paramSTR)
    paramINT = int(paramSTR)
    GlmParamList[i] = paramINT

[ MAXVALUE, PRECISION, PRECISIONDECIMALSIZE, PRECISIONDECIMALSIZEX, 
PLAINTEXTPRIMESIZE, PLAINTEXTBITSIZE, REGRLOOPCOUNT, NUMTHREADS] = GlmParamList
t1 = time.time()
timing["RecvParam"] = timing["RecvParam"] + (t1-t0)
print 'Completed'
print 'Parameters\n', GlmParamList

##########################################################

glm.SetGLMParams(GlmParamList)

print '\nRecv:   Key and CryptoContext...',
t0 = time.time()
for i in range(PLAINTEXTPRIMESIZE):
    
    pubKeyPath = keyDir+"/"+keyfileName+"-public" + str(i) + ".txt"
    fileTransfer.recieveFile(pubKeyPath, sock)

    evalKeyMultPath = keyDir+"/"+keyfileName+"-eval-mult" + str(i) + ".txt"
    fileTransfer.recieveFile(evalKeyMultPath, sock)
    
    evalKeySumPath  = keyDir+"/"+keyfileName+"-eval-sum" + str(i) + ".txt"
    fileTransfer.recieveFile(evalKeySumPath, sock)
    
    cryptoContPath  = keyDir+"/"+keyfileName+"-cryptocontext" + str(i) + ".txt"
    fileTransfer.recieveFile(cryptoContPath, sock)

t1 = time.time()
timing["RecvKeyCrypt"] = timing["RecvKeyCrypt"] + (t1-t0)    
print 'Completed'    
##########################################################

print 'Recv:   X and Y...',
t0 = time.time()
for i in range(PLAINTEXTPRIMESIZE):
        
    ciphertextXPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextXFileName+"-" + str(i) + ".txt"
    fileTransfer.recieveFile(ciphertextXPath, sock)
    
    ciphertextYPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextYFileName+"-" + str(i) + ".txt"
    fileTransfer.recieveFile(ciphertextYPath, sock)
        
t1 = time.time()
timing["RecvXY"] = timing["RecvXY"] + (t1-t0)
print 'Completed'

##########################################################

glm.SetGLMContext()
    
for loop in range(REGRLOOPCOUNT):    
    totalstart = time.time()
    print '\n'
    print '########################################################'
    print '         Iteration ', loop
    print '########################################################'
    
    print 'Recv:   W...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):

        ciphertextWPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextWFileName+"-" + str(i) + ".txt"
        fileTransfer.recieveFile(ciphertextWPath, sock)

    t1 = time.time()
    timing["RecvW"] = timing["RecvW"] + (t1-t0)
    print 'Completed'
    
    ##########################################################
    
    print 'Comp:   X*W (Step-1)...',
    t0 = time.time()
    glm.Step1ComputeXW()
    t1 = time.time()
    timing["ComputeStep1"] = timing["ComputeStep1"] + (t1-t0)
    print 'Completed'
    
    ##########################################################
    
    print 'Send:   X*W...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):

        ciphertextXWPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextXWFileName+"-" + str(i) + ".txt"
        fileTransfer.sendFile(ciphertextXWPath, sock)
        
    t1 = time.time()
    timing["SendXW"] = timing["SendXW"] + (t1-t0)
    print 'Completed'
    
    ##########################################################
      
    print 'Recv:   Mu and S...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):
        
        ciphertextMUPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextMUFileName+"-"+ str(i) + ".txt"
        fileTransfer.recieveFile(ciphertextMUPath, sock)
    
        ciphertextSPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextSFileName+"-"+ str(i) + ".txt"
        fileTransfer.recieveFile(ciphertextSPath, sock)

    t1 = time.time()
    timing["RecvMuS"] = timing["RecvMuS"] + (t1-t0)
    print 'Completed'
    
    ##########################################################
 
    print 'Comp:   C1=X^T*S*X (Step-2)...',
    t0 = time.time()
    glm.Step2ComputeXTSX()
    t1 = time.time()
    timing["ComputeStep2"] = timing["ComputeStep2"] + (t1-t0)
    print 'Completed'

    ##########################################################
  
    print 'Send:   C1=X^T*S*X...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):
    
        ciphertextXTXPath = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextC1FileName+"-" + str(i) + ".txt"
        fileTransfer.sendFile(ciphertextXTXPath, sock)
    
    t1 = time.time()
    timing["SendXTSX"] = timing["SendXTSX"] + (t1-t0)
    print 'Completed'
    
    ##########################################################
    
    print 'Recv:   C1^{-1}=(X^T*S*X)^{-1} ...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):
    
        ciphertextC1Path = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextC1FileName+"-" + str(i) + ".txt"
        fileTransfer.recieveFile(ciphertextC1Path, sock)
 
    t1 = time.time()
    timing["RecvC1"] = timing["RecvC1"] + (t1-t0)
    print 'Completed'
    
    ##########################################################

    print 'Comp:   w + C1^{-1}*C2 = w + (X^T*S*X)^{-1}*X^T*(y-mu)...',
    t0 = time.time()
    glm.Step3ComputeRegressor()
    t1 = time.time()
    timing["ComputeStep3"] = timing["ComputeStep3"] + (t1-t0)
    print 'Completed'
    
    ##########################################################

    print 'Send:   W...',
    t0 = time.time()
    for i in range(PLAINTEXTPRIMESIZE):

        ciphertextC1C2Path = ciphertextDataDir+"/"+ciphertextDataFileName+"-"+ciphertextC1C2FileName+"-" + str(i) + ".txt"
        fileTransfer.sendFile(ciphertextC1C2Path, sock)
    t1 = time.time()

    timing["SendC1-2"] = timing["SendC1-2"] + (t1-t0)
    print 'Completed'
    
    totalend = time.time()
    print 'Time for Loop', loop,':', (totalend-totalstart)

sock.close()

##########################################################
##########################################################
##########################################################
'''
print timing

l = [i for i in timing.items()]
for i in range(len(l)):
    print l[i][0], '\t', l[i][1]
'''
##########################################################
##########################################################
##########################################################

print '\n'
print '################################'
print '   Timings '
print '################################'

print "ComputeStep1:   ", timing["ComputeStep1"]
print "SendXW:         ", timing["SendXW"]

print "ComputeStep2:   ", timing["ComputeStep2"]
print "SendXTSX:       ", timing["SendXTSX"]

print "ComputeStep3:   ", timing["ComputeStep3"]
print "SendC1:         ", timing["SendC1-2"]

glm.PrintTimings()







