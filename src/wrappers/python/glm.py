import csv
import numpy as np

def writeCSV2Mat(path):
    mat = np.genfromtxt(path, delimiter=',')
    return mat

#plaintextDataDir        = "demoData/python/glm/client/plaintextDataDir"
#plaintextDataFileName   = "rev_10k_poisson.csv"
#regAlg = "Poisson"

def Compute(filePath, matW, regAlg):

    matM = writeCSV2Mat(filePath)

    matM = matM[1:len(matM)]
    matM = matM[:,1:len(matM[0])]
    matM = np.mat(matM)

    matONEs = np.ones(len(matM))
    matONEs = np.mat(matONEs)
    matONEs = matONEs.transpose()

    matX = matM[:,1:]
    matX = np.hstack((matONEs, matX))

    matY = matM[:,0]

    [row, col] = matX.shape

    if matW == []:
        matW = [0.0 for x in range(col)]
        matW = np.mat(matW)
        matW = matW.transpose()

    for loop in range(1):
        matZ = matW.transpose() * matX.transpose()

        matMU = []
        matS = []

        if regAlg == "NORMAL":
            matMU = matZ
            matS  = [1.0 for x in range(row)]
        elif regAlg == "POISSON":
            matMU = np.exp(matZ)
            matS  = matMU
        elif regAlg == "LOGISTIC":
            matMU = 1/(1+np.exp(matZ))
            matS  = np.multiply(matMU, np.ones(len(matMU))-matMU)#[matMU[x] for x in range(row)]

        matC1 = []
        for i in range(col):

            x = np.multiply(matX.transpose()[i], matS)
            if i==0:
                matC1 = x
            else:
                matC1 = np.vstack((matC1, x))

        matC1 = (matC1*matX)
        matC1Inv = matC1.I

        matC2 = np.subtract(matY, matMU.transpose())
        matC2 = matX.transpose()*matC2

        matC = matC1Inv*matC2

        matW = matW+matC



    return matW
