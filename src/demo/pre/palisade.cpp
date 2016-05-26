//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	6/17/2015 4:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Jerry Ryan, gwryan@njit.edu
Description:
	This code provides a command line to exercise the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.

	We configured parameters (namely the ring dimension and ciphertext modulus)
	to provide a level of security roughly equivalent to a root hermite factor of 1.007
	which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor
	and may be closer to AES-256.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#include <string>
#include <iostream>
using namespace std;

#include "math/backend.h"
#include "utils/inttypes.h"

#include "lattice/ilparams.h"

#include "crypto/lwecrypt.h"
#include "crypto/lwecrypt.cpp"
#include "crypto/lwepre.h"
#include "crypto/lwepre.cpp"
#include "crypto/lweahe.h"
#include "crypto/lweahe.cpp"
#include "crypto/lweshe.h"
#include "crypto/lweshe.cpp"
#include "crypto/lwefhe.h"
#include "crypto/lwefhe.cpp"
#include "crypto/lweautomorph.h"
#include "crypto/lweautomorph.cpp"

#include "crypto/ciphertext.h"
#include "crypto/ciphertext.cpp"

#include "utils/serializablehelper.h"

using namespace lbcrypto;

void usage(const string& cmd, const string& msg = "");

template<typename T>
bool fetchItemFromSer(T* key, const string& filename)
{
	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(filename, &kser) ) {
		return key->Deserialize(kser);
	} else {
		cerr << "Error reading from file " << filename << endl;
	}
	return false;
}

void
applyFunctionToChunksOfInput(istream *in )
{

}

class	PalisadeControls {
public:
	usint				cyclOrder;
	BigBinaryInteger	modulus;
	BigBinaryInteger	rootOfUnity;
	usint				relinWindow;
	float				stdDev;

	long				chunkSize;

	ILParams			ilParams;
	LPCryptoParametersLTV<ILVector2n> *cryptoParams;
} ctlCrypt;

typedef void (*cmdparser)(string cmd, int argc, char *argv[]);

void
reencrypter(string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string ciphertextname(argv[0]);
	string rekeyname(argv[1]);
	string reciphertextname(argv[2]);

	LPEvalKeyLTV<ILVector2n> evalKey(*ctlCrypt.cryptoParams);
	if( !fetchItemFromSer(&evalKey, rekeyname) ) {
		cerr << "Could not process re encryption key" << endl;
		return;
	}

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	ofstream outCt(reciphertextname, ios::binary);
	if( !outCt.is_open() ) {
		cerr << "Could not open re-encryption file";
		return;
	}

	Ciphertext<ILVector2n> ciphertext;
	Ciphertext<ILVector2n> newCiphertext;

	ifstream inCt(ciphertextname, ios::binary);
	if( !inCt.is_open() ) {
		cerr << "Could not process ciphertext" << endl;
		outCt.close();
		return;
	}

	string inBuf;
	char ch;

	do {
		inBuf = "";
		while( (ch = inCt.get()) != EOF && ch != '$' )
			inBuf += ch;

		if( ch == EOF ) break;

		Serialized ser;
		if( !SerializableHelper::StringToSerialization(inBuf, &ser) ) {
			cerr << "Error deserializing ciphertext" << endl;
			break;
		}

		if( !ciphertext.Deserialize(ser) ) {
			cerr << "Error deserializing ciphertext" << endl;
			break;
		}

		algorithm.ReEncrypt(evalKey, ciphertext, &newCiphertext);

		Serialized cipS;
		string reSerialized;

		if( newCiphertext.Serialize(&cipS, "Re") ) {
			if( !SerializableHelper::SerializationToString(cipS, reSerialized) ) {
				cerr << "Error creating serialization of new ciphertext" << endl;
				return;
			}

			outCt << reSerialized << '$' << flush;
		}
		else {
			cerr << "Error reserializing ciphertext" << endl;
			break;
		}

	} while( inCt.good() );

	inCt.close();
	outCt.close();
	return;
}

void
decrypter(string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string ciphertextname(argv[0]);
	string prikeyname(argv[1]);
	string cleartextname(argv[2]);

	LPPrivateKeyLTV<ILVector2n> sk(*ctlCrypt.cryptoParams);
	if( !fetchItemFromSer(&sk, prikeyname) ) {
		cerr << "Could not process private key" << endl;
		return;
	}

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	ofstream outF(cleartextname, ios::binary);
	if( !outF.is_open() ) {
		cerr << "Could not open cleartext file";
		return;
	}

	ifstream inCt(ciphertextname, ios::binary);
	if( !inCt.is_open() ) {
		cerr << "Could not process ciphertext" << endl;
		outF.close();
		return;
	}

	Ciphertext<ILVector2n> ciphertext;
	ByteArrayPlaintextEncoding plaintext;

	string inBuf;
	char ch;

	do {
		inBuf = "";
		while( (ch = inCt.get()) != EOF && ch != '$' )
			inBuf += ch;

		if( ch == EOF ) break;

		Serialized ser;
		if( !SerializableHelper::StringToSerialization(inBuf, &ser) ) {
			cerr << "Error deserializing ciphertext" << endl;
			break;
		}

		if( !ciphertext.Deserialize(ser) ) {
			cerr << "Error deserializing ciphertext" << endl;
			break;
		}

		DecodingResult rv = algorithm.Decrypt(sk, ciphertext, &plaintext);
		plaintext.Unpad<ZeroPad>();

		outF << plaintext << flush;

	} while( inCt.good() );

	inCt.close();
	outF.close();

	return;
}

void
encrypter(string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string plaintextname(argv[0]);
	string pubkeyname(argv[1]);
	string ciphertextname(argv[2]);

	ofstream ctSer(ciphertextname, ios::binary);
	if( !ctSer.is_open() ) {
		cerr << "could not open output file " << ciphertextname << endl;
		return;
	}

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(*ctlCrypt.cryptoParams);

	if( !fetchItemFromSer(&pk, pubkeyname) ) {
		cerr << "Could not process public key" << endl;
		ctSer.close();
		return;
	}

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	// fetch the plaintext to be encrypted
	ifstream inf(plaintextname, ios::binary);
	if( !inf.is_open() ) {
		cerr << "could not read plaintext file " << plaintextname << endl;
		ctSer.close();
		return;
	}

	inf.seekg(0, ios::end);
	long totalBytes = inf.tellg();
	inf.clear();
	inf.seekg(0);


	while( totalBytes > 0 ) {
		usint s = min(totalBytes, ctlCrypt.chunkSize);
		char *chunkb = new char[s];
		inf.read(chunkb, s);

		ByteArrayPlaintextEncoding ptxt(chunkb);
		ptxt.Pad<ZeroPad>(ctlCrypt.cyclOrder/16);
		delete chunkb;

		Ciphertext<ILVector2n> ciphertext;

		algorithm.Encrypt(pk, ptxt, &ciphertext);
		Serialized cipS;
		string cipherSer;

		if( ciphertext.Serialize(&cipS, "Enc") ) {
			if( !SerializableHelper::SerializationToString(cipS, cipherSer) ) {
				cerr << "Error stringifying serialized ciphertext" << endl;
				break;
			}

			ctSer << cipherSer << "$" << flush;
		} else {
			cerr << "Error serializing ciphertext" << endl;
			break;
		}

		totalBytes -= ctlCrypt.chunkSize;
	}

	inf.close();
	ctSer.close();
	return;
}

void
rekeymaker(string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string pubname(argv[0]);
	string privname(argv[1]);
	string rekeyname(argv[2]);

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(*ctlCrypt.cryptoParams);
	LPPrivateKeyLTV<ILVector2n> sk(*ctlCrypt.cryptoParams);

	if( !fetchItemFromSer(&pk, pubname) ) {
		cerr << "Could not process public key" << endl;
		return;
	}

	if( !fetchItemFromSer(&sk, privname) ) {
		cerr << "Could not process private key" << endl;
		return;
	}

	LPEvalKeyLTV<ILVector2n> evalKey(*ctlCrypt.cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	if( algorithm.EvalKeyGen(pk, sk, &evalKey) ) {
		Serialized evalK;

		if( evalKey.Serialize(&evalK, rekeyname) ) {
			if( !SerializableHelper::WriteSerializationToFile(evalK, rekeyname) ) {
				cerr << "Error writing serialization of recryption key to " + rekeyname << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing recryption key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating recryption key" << endl;
	}

	return;
}

void
keymaker(string cmd, int argc, char *argv[]) {
	if( argc != 1 ) {
		usage(cmd, "missing keyname");
		return;
	}

	string keyname(argv[0]);

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(*ctlCrypt.cryptoParams);
	LPPrivateKeyLTV<ILVector2n> sk(*ctlCrypt.cryptoParams);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	if( algorithm.KeyGen(&pk,&sk) ) {
		Serialized pubK, privK;

		if( pk.Serialize(&pubK, keyname) ) {
			if( !SerializableHelper::WriteSerializationToFile(pubK, keyname + "PUB.txt") ) {
				cerr << "Error writing serialization of public key to " + keyname + "PUB.txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing public key" << endl;
			return;
		}

		if( sk.Serialize(&privK, keyname) ) {
			if( !SerializableHelper::WriteSerializationToFile(privK, keyname + "PRI.txt") ) {
				cerr << "Error writing serialization of private key to " + keyname + "PRI.txt" << endl;
				return;
			}
		}
		else {
			cerr << "Error serializing private key" << endl;
			return;
		}
	} else {
		cerr << "Failure in generating keys" << endl;
	}

	return;
}

struct {
	string		command;
	cmdparser	func;
	string		helpline;
} cmds[] = {
		"makekey", keymaker, " [optional key parms] keyname\n"
			"\tcreate a new keypair and save in keyfilePUB.txt and keyfilePRI.txt",
		"makerekey", rekeymaker, " [optional key parms] pubkey_file secretkey_file rekey_file\n"
			"\tcreate a re-encryption key from the contents of pubkey_file and secretkey_file, save in rekey_file",
		"encrypt", encrypter, " [optional parms] plaintext_file pubkey_file ciphertext_file\n"
			"\tencrypt the contents of plaintext_file using the contents of pubkey_file, save results in ciphertext_file",
		"reencrypt", reencrypter, " [optional parms] encrypted_file rekey_file reencrypted_file\n"
			"\treencrypt the contents of encrypted_file using the contents of rekey_file, save results in reencrypted_file",
		"decrypt", decrypter,  " [optional parms] ciphertext_file prikey_file cleartext_file\n"
			"\tdecrypt the contents of ciphertext_file using the contents of prikey_file, save results in cleartext_file",

};

void
usage(const string& cmd, const string& msg)
{
	if( msg.length() > 0 )
		cerr << msg << endl;

	cerr << "Usage is:" << endl;
	for( int i=0; i<sizeof(cmds)/sizeof(cmds[0]); i++ ) {
		if( cmd == "ALL" || cmd == cmds[i].command )
			cerr << "palisade " << cmds[i].command << cmds[i].helpline << endl;
	}
}

int
main( int argc, char *argv[] )
{
	if( argc < 2 ) {
		usage("ALL");
		return 1;
	}

	ctlCrypt.cyclOrder = 2048;
	ctlCrypt.modulus = BigBinaryInteger("268441601");
	ctlCrypt.rootOfUnity = BigBinaryInteger("16947867");
	ctlCrypt.relinWindow = 1;
	ctlCrypt.stdDev = 4;

	ctlCrypt.chunkSize = (ctlCrypt.cyclOrder / 2) / 8; // bytes

	ctlCrypt.ilParams = ILParams(ctlCrypt.cyclOrder, ctlCrypt.modulus, ctlCrypt.rootOfUnity);

	//Set crypto parametes
	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	ctlCrypt.cryptoParams = &cryptoParams;
	ctlCrypt.cryptoParams->SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
	ctlCrypt.cryptoParams->SetDistributionParameter(ctlCrypt.stdDev);			// Set the noise parameters.
	ctlCrypt.cryptoParams->SetRelinWindow(ctlCrypt.relinWindow);				// Set the relinearization window
	ctlCrypt.cryptoParams->SetElementParams(ctlCrypt.ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg(ctlCrypt.stdDev);				// Create the noise generator
	ctlCrypt.cryptoParams->SetDiscreteGaussianGenerator(dgg);

	bool	rancmd = false;
	string userCmd(argv[1]);
	for( int i=0; i<(sizeof(cmds)/sizeof(cmds[0])); i++ ) {
		if( cmds[i].command == string(userCmd) ) {
			(*cmds[i].func)(cmds[i].command, argc-2, &argv[2]);
			rancmd = true;
			break;
		}
	}

	if( !rancmd ) {
		usage("ALL", "invalid command " + userCmd);
		return 1;
	}

	return 0;
}
