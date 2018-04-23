import os
import numpy as np

BUFFER_SIZE = (1024*8)

def writeCSV2Mat(path):
	mat = np.genfromtxt(path, delimiter=',')
	return mat

def writeMat2CSV(mat, path):
    matnp = np.array(mat)
    np.savetxt(path, matnp, delimiter=",")

def sendAck(connection):
	connection.send("Complete")

def waitAck(connection):
	ack = connection.recv(1024)
	if ack == "Complete":
		return 1 #print 'Ack Complete'
	else:
		raise Exception("Acknowledgement Error")

def clearPadding(str):
	while str[len(str)-1] == "F":
		str = str[0:len(str)-1]
	return str

def padding(l):
    while len(l)<32:
        l = l + "F"
    return l

def recieveFile(file, connection):
	f = open(file,'wb') #open in binary
	fSizeStr = connection.recv(32)
	fSizeStr = clearPadding(fSizeStr)
#	print 'File Size\t', fSizeStr
	fSize = int(fSizeStr)
	while fSize:
		if fSize > BUFFER_SIZE:
			l = connection.recv(BUFFER_SIZE)
			fSize = fSize - BUFFER_SIZE
		else:
			l = connection.recv(fSize)
			fSize = 0
		f.write(l)
		sendAck(connection)
	f.close()
#	print 'File Recieve Complete'

def sendFile(file, connection):
    f = open(file,'rb') #open in binary
    fSize = os.path.getsize(file)
    fSizeStr = padding(str(fSize))
    s = fSizeStr.encode()
    connection.send(s)
    while fSize:
        if fSize > BUFFER_SIZE:
            fRead = f.read(BUFFER_SIZE)
            fSize = fSize - BUFFER_SIZE
        else:
            fRead = f.read(fSize)
            fSize = 0
        connection.send(fRead)
        waitAck(connection)
    f.close()
#    print 'File Send Complete'
