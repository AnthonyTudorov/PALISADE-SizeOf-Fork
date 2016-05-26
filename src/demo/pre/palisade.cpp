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

class	PalisadeControls {
public:
	usint				ring;
	BigBinaryInteger	modulus;
	BigBinaryInteger	rootOfUnity;
	usint				relinWindow;
	float				stdDev;

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

	Ciphertext<ILVector2n> ciphertext;
	if( !fetchItemFromSer(&ciphertext, ciphertextname) ) {
		cerr << "Could not process ciphertext" << endl;
		return;
	}

	LPEvalKeyLTV<ILVector2n> evalKey(*ctlCrypt.cryptoParams);
	if( !fetchItemFromSer(&evalKey, rekeyname) ) {
		cerr << "Could not process re encryption key" << endl;
		return;
	}

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	Ciphertext<ILVector2n> newCiphertext;

	algorithm.ReEncrypt(evalKey, ciphertext, &newCiphertext);
	Serialized cipS;

	if( newCiphertext.Serialize(&cipS, "Enc") ) {
		if( !SerializableHelper::WriteSerializationToFile(cipS, reciphertextname) ) {
			cerr << "Error writing serialization of new ciphertext to " + reciphertextname << endl;
			return;
		}
	}
	else {
		cerr << "Error reserializing ciphertext" << endl;
		return;
	}

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

	Ciphertext<ILVector2n> ciphertext;
	if( !fetchItemFromSer(&ciphertext, ciphertextname) ) {
		cerr << "Could not process ciphertext" << endl;
		return;
	}

	LPPrivateKeyLTV<ILVector2n> sk(*ctlCrypt.cryptoParams);
	if( !fetchItemFromSer(&sk, prikeyname) ) {
		cerr << "Could not process private key" << endl;
		return;
	}

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	ByteArrayPlaintextEncoding plaintext;

	DecodingResult rv = algorithm.Decrypt(sk, ciphertext, &plaintext);
	cout << "Decrypted plaintext of size " << plaintext.GetLength() << ":" << rv.isValidCoding << ":" << rv.messageLength << endl;
	plaintext.Unpad<ZeroPad>();
	cout << "unpadded " << plaintext.GetLength() << endl;

	ofstream outf(cleartextname);
	if( !outf.is_open() ) {
		cerr << "Error saving plaintext" << endl;
		return;
	}


	outf << plaintext;
	outf.close();
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

	// fetch the plaintext to be encrypted
	ifstream inf(plaintextname);
	if( !inf.is_open() ) {
		cerr << "could not read plaintext file " << plaintextname << endl;
		return;
	}
	stringstream buffer;
	buffer << inf.rdbuf();
	inf.close();

	ByteArrayPlaintextEncoding ptxt(buffer.str());
	ptxt.Pad<ZeroPad>(ctlCrypt.ring/16);

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(*ctlCrypt.cryptoParams);

	if( !fetchItemFromSer(&pk, pubkeyname) ) {
		cerr << "Could not process public key" << endl;
		return;
	}

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	Ciphertext<ILVector2n> ciphertext;

	algorithm.Encrypt(pk, ptxt, &ciphertext);
	Serialized cipS;

	if( ciphertext.Serialize(&cipS, "Enc") ) {
		if( !SerializableHelper::WriteSerializationToFile(cipS, ciphertextname) ) {
			cerr << "Error writing serialization of ciphertext to " + ciphertextname << endl;
			return;
		}
	}
	else {
		cerr << "Error serializing ciphertext" << endl;
		return;
	}

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
tryit()
{
	string plaintextname("plaintextMessage");
	string pubkeyname("publisherPUB.txt");
	string prikeyname("publisherPRI.txt");

	// fetch the plaintext to be encrypted
	ifstream inf(plaintextname);
	if( !inf.is_open() ) {
		cerr << "could not read plaintext file " << plaintextname << endl;
		return;
	}
	stringstream buffer;
	buffer << inf.rdbuf();
	inf.close();

	ByteArrayPlaintextEncoding ptxt(buffer.str());
	ptxt.Pad<ZeroPad>(ctlCrypt.ring/16);

	LPPublicKeyLTV<ILVector2n> pk(*ctlCrypt.cryptoParams);
	if( !fetchItemFromSer(&pk, pubkeyname) ) {
		cerr << "Could not process public key" << endl;
		return;
	}
	LPPrivateKeyLTV<ILVector2n> sk(*ctlCrypt.cryptoParams);
	if( !fetchItemFromSer(&sk, prikeyname) ) {
		cerr << "Could not process private key" << endl;
		return;
	}

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	Ciphertext<ILVector2n> ciphertext;
	ByteArrayPlaintextEncoding cleartext;

	algorithm.Encrypt(pk, ptxt, &ciphertext);

	algorithm.Decrypt(sk, ciphertext, &cleartext);

	cout << cleartext << endl;
	return;

}

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

	ctlCrypt.ring = 2048;
	ctlCrypt.modulus = BigBinaryInteger("268441601");
	ctlCrypt.rootOfUnity = BigBinaryInteger("16947867");
	ctlCrypt.relinWindow = 1;
	ctlCrypt.stdDev = 4;

	ctlCrypt.ilParams = ILParams(ctlCrypt.ring, ctlCrypt.modulus, ctlCrypt.rootOfUnity);

	//Set crypto parametes
	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	ctlCrypt.cryptoParams = &cryptoParams;
	ctlCrypt.cryptoParams->SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
	ctlCrypt.cryptoParams->SetDistributionParameter(ctlCrypt.stdDev);			// Set the noise parameters.
	ctlCrypt.cryptoParams->SetRelinWindow(ctlCrypt.relinWindow);				// Set the relinearization window
	ctlCrypt.cryptoParams->SetElementParams(ctlCrypt.ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg(ctlCrypt.stdDev);				// Create the noise generator
	ctlCrypt.cryptoParams->SetDiscreteGaussianGenerator(dgg);

	tryit();

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
