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

#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/serializablehelper.h"
#include "../../lib/encoding/byteencoding.h"
#include "../../lib/encoding/cryptoutility.h"

using namespace lbcrypto;

void usage(const string& cmd, const string& msg = "");

template<typename T>
bool fetchItemFromSer(T* key, const string& filename, const CryptoContext<ILVector2n>* ctx)
{
	Serialized	kser;
	if( SerializableHelper::ReadSerializationFromFile(filename, &kser) ) {
		return key->Deserialize(kser, ctx);
	} else {
		cerr << "Error reading from file " << filename << endl;
	}
	return false;
}

typedef void (*cmdparser)(CryptoContext<ILVector2n> *ctx, string cmd, int argc, char *argv[]);

void
reencrypter(CryptoContext<ILVector2n> *ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string ciphertextname(argv[0]);
	string rekeyname(argv[1]);
	string reciphertextname(argv[2]);

	LPEvalKeyLTV<ILVector2n> evalKey(*ctx->getParams());
	if( !fetchItemFromSer(&evalKey, rekeyname, ctx) ) {
		cerr << "Could not process re encryption key" << endl;
		return;
	}

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

	CryptoUtility<ILVector2n>::ReEncrypt(ctx, evalKey, inCt, outCt);

	inCt.close();
	outCt.close();
	return;
}

void
decrypter(CryptoContext<ILVector2n> *ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string ciphertextname(argv[0]);
	string prikeyname(argv[1]);
	string cleartextname(argv[2]);

	LPPrivateKeyLTV<ILVector2n> sk(*ctx->getParams());
	if( !fetchItemFromSer(&sk, prikeyname, ctx) ) {
		cerr << "Could not process private key" << endl;
		return;
	}

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

	CryptoUtility<ILVector2n>::Decrypt(ctx, sk, inCt, outF);

	inCt.close();
	outF.close();

	return;
}

void
encrypter(CryptoContext<ILVector2n> *ctx, string cmd, int argc, char *argv[]) {
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
	LPPublicKeyLTV<ILVector2n> pk(*ctx->getParams());

	if( !fetchItemFromSer(&pk, pubkeyname, ctx) ) {
		cerr << "Could not process public key" << endl;
		ctSer.close();
		return;
	}

	// fetch the plaintext to be encrypted
	ifstream inf(plaintextname, ios::binary);
	if( !inf.is_open() ) {
		cerr << "could not read plaintext file " << plaintextname << endl;
		ctSer.close();
		return;
	}

	EncryptResult er = CryptoUtility<ILVector2n>::Encrypt(ctx, pk, inf, ctSer);

	if( !er.isValid ) {
		cerr << "failed to encrypt" << endl;
	}

	inf.close();
	ctSer.close();
	return;
}

void
rekeymaker(CryptoContext<ILVector2n> *ctx, string cmd, int argc, char *argv[]) {
	if( argc != 3 ) {
		usage(cmd, "missing arguments");
		return;
	}

	string pubname(argv[0]);
	string privname(argv[1]);
	string rekeyname(argv[2]);

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(*ctx->getParams());
	LPPrivateKeyLTV<ILVector2n> sk(*ctx->getParams());

	if( !fetchItemFromSer(&pk, pubname, ctx) ) {
		cerr << "Could not process public key" << endl;
		return;
	}

	if( !fetchItemFromSer(&sk, privname, ctx) ) {
		cerr << "Could not process private key" << endl;
		return;
	}

	LPEvalKeyLTV<ILVector2n> evalKey(*ctx->getParams());

	if( ctx->getAlgorithm()->EvalKeyGen(pk, sk, &evalKey) ) {
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
keymaker(CryptoContext<ILVector2n> *ctx, string cmd, int argc, char *argv[]) {
	if( argc != 1 ) {
		usage(cmd, "missing keyname");
		return;
	}

	string keyname(argv[0]);

	// Initialize the public key containers.
	LPPublicKeyLTV<ILVector2n> pk(*ctx->getParams());
	LPPrivateKeyLTV<ILVector2n> sk(*ctx->getParams());

	if( ctx->getAlgorithm()->KeyGen(&pk,&sk) ) {
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
		"makekey", keymaker, " [optional parms] keyname\n"
		"\tcreate a new keypair and save in keyfilePUB.txt and keyfilePRI.txt",
		"makerekey", rekeymaker, " [optional parms] pubkey_file secretkey_file rekey_file\n"
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

	for( int i=0; i<sizeof(cmds)/sizeof(cmds[0]); i++ ) {
		if( cmd == "ALL" || cmd == cmds[i].command )
			cerr << "palisade " << cmds[i].command << cmds[i].helpline << endl;
	}

	cerr << endl;
	cerr << "[optional params] are:" << endl;
	cerr << "-list filename: list all the parameter sets in the file filename, then exit" << endl;
	cerr << "-use filename parmset: use the parameter set named parmset from the parameter file" << endl;
	cerr << "-from filename: use the deserialization of filename to set the crypto context" << endl;

	std::cin.get();
}

int
main( int argc, char *argv[] )
{
	if( argc < 2 ) {
		usage("ALL");
		return 1;
	}

	if( string(argv[1]) == "-list" && argc == 3) {
		CryptoContextHelper<ILVector2n>::printAllParmSets(cout, argv[2]);
		return 0;
	}

	CryptoContext<ILVector2n> *ctx = 0;

	int cmdidx = 1;
	if( string(argv[1]) == "-use" && argc >= 4) {
		ctx = CryptoContextHelper<ILVector2n>::getNewContext( string(argv[2]), string(argv[3]) );
		if( ctx == 0 ) {
			usage("ALL", "Could not construct a crypto context");
			return 1;
		}

		cmdidx += 3;
	}
	else if( string(argv[1]) == "-from" && argc >= 3 ) {
		Serialized	kser;
		if( SerializableHelper::ReadSerializationFromFile(string(argv[2]), &kser) ) {
			ctx = CryptoContextHelper<ILVector2n>::getNewContextFromSerialization(kser);
		}

		cmdidx += 2;
	}
	else {
		ctx = CryptoContext<ILVector2n>::genCryptoContextLTV(2, 2048, "268441601", "16947867", 1, 4);
	}

	if( ctx == 0 ) {
		usage("ALL", "Unable to create a crypto context");
		return 1;
	}

	if( cmdidx >= argc ) {
		usage("ALL");
		return 1;
	}

	bool	rancmd = false;
	string userCmd(argv[cmdidx]);
	for( int i=0; i<(sizeof(cmds)/sizeof(cmds[0])); i++ ) {
		if( cmds[i].command == string(userCmd) ) {
			(*cmds[i].func)(ctx, cmds[i].command, argc-1-cmdidx, &argv[cmdidx + 1]);
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
