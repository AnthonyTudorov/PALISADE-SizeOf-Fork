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
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
		Jerry Ryan, gwryan@njit.edu
Description:
	This code demonstrates how to Encrypt and Re-encrypt byte data using the NJIT LATTICE library.
	In this code we:
		- Generate a key pair.
		- Encrypt a string of data.
		- Decrypt the data.
		- Generate a new key pair.
		- Generate a proxy re-encryption key.
		- Re-Encrypt the encrypted data.
		- Decrypt the re-encrypted data.

	We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to
	a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational
	work factor and may be closer to AES-256.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

#include <iostream>
#include <fstream>
#include <string>
#include <iterator>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"

#include "cryptocontextparametersets.h"

#include "utils/debug.h"
using namespace std;
using namespace lbcrypto;

////////////////////////////////////////////////////////////
// This program demonstrates the use of the PALISADE library to encrypt bytes of text
//
// All PALISADE functionality takes place as a part of a CryptoContext, and so the first
// step in using PALISADE is creating a CryptoContext
//
// A CryptoContext can be created on the fly by passing parameters into a method provided
// in the CryptoContextFactory.
// A CryptoContext can be custom tuned for your particular application by using parameter generation
// A CryptoContext can be constructed from one of a group of named, predetermined parameter sets
//
// This program uses the "group of named predetermined sets" method. Pass the parameter set name to the
// program and it will use that set. Pass no names and it will tell you all the available names.
// Use the -v option and the program will be verbose as it operates


int main(int argc, char *argv[])
{
	string parmSetName;
	bool beVerbose = false;
	bool haveName = false;

	// Process parameters, find the parameter set name specified on the command line
	for( int i=1; i<argc; i++ ) {
		string parm( argv[i] );

		if( parm[0] == '-' ) {
			if( parm == "-v" )
				beVerbose = true;
			else {
				cout << "Unrecognized parameter " << parm << endl;
				return 1;
			}
		}

		else {
			if( haveName ) {
				cout << "Cannot specify multiple parameter set names" << endl;
				return 1;
			}

			haveName = true;
			parmSetName = parm;

		}
	}

	// If a name has been specified, make sure it is recognized
	if( haveName ) {
		auto parmfind = CryptoContextParameterSets.find(parmSetName);
		if( parmfind == CryptoContextParameterSets.end() ) {
			cout << "Parameter set " << parmSetName << " is not a recognized name" << endl;
			haveName = false;
		}
	}

	// no name specified? print out the names of all available parameter sets
	if( !haveName ) {
		cout << "Available crypto parameter sets are:" << endl;
		CryptoContextHelper<ILVector2n>::printAllParmSetNames(cout);
		return 1;
	}

	if( beVerbose ) {
		CryptoContextHelper<ILVector2n>::printParmSet(cout, parmSetName);
	}

	// Construct a crypto context for this parameter set

	if( beVerbose ) cout << "Initializing crypto system" << endl;

	CryptoContext<ILVector2n> cc = CryptoContextHelper<ILVector2n>::getNewContext(parmSetName);

	// enable features that you wish to use
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	// Plaintext in this case is a BytePlaintextEncoding
	BytePlaintextEncoding plaintext;

	// The plaintext is broken up into chunks of size chunksize
	size_t chunksize = plaintext.GetChunksize(cc.GetCyclotomicOrder(), cc.GetCryptoParameters()->GetPlaintextModulus());

	if( beVerbose ) cout << "Encryption will be in chunks of size " << chunksize << endl;

	// generate a random string of length chunksize
	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};

	string rchars(chunksize,0);
	std::generate_n(rchars.begin(), chunksize, randchar);


	// create a plaintext object from that string
	plaintext = rchars;

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	if( beVerbose ) cout << "Running key generation" << endl;

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	if ( !kp.good() ) {
		cout << "Key generation failed" << endl;
		return 1;
	}

	////////////////////////////////////////////////////////////
	// Encryption
	//
	// The Encrypt routine splits the input into chunks of size "chunksize"
	// and encrypts each chunk into a ciphertext. We expect only one entry
	// in the resulting table
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	if( beVerbose ) cout << "Running encryption" << endl;

	// we tell Encrypt not to pad this entry by using false for the third parameter;
	// if we said true instead, padding would be added on Encrypt and removed on Decrypt
	ciphertext = cc.Encrypt(kp.publicKey, plaintext, false);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	if( beVerbose ) cout << "Running decryption" << std::endl;

	DecryptResult result = cc.Decrypt(kp.secretKey,ciphertext,&plaintextNew,false);

	if (!result.isValid) {
		cout << "Decryption failed" << endl;
		return 1;
	}

	if( plaintext != plaintextNew ) {
		cout << "Mismatch on decryption" << endl;
		return 1;
	}

	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	if( beVerbose ) cout << "Running second key generation (used for re-encryption)" << endl;

	LPKeyPair<ILVector2n> newKp = cc.KeyGen();

	if ( !newKp.good() ) {
		cout << "Key generation failed" << endl;
		return 1;
	}

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	if( beVerbose ) cout << "Generating proxy re-encryption key" << endl;

	shared_ptr<LPEvalKey<ILVector2n>> evalKey;
	try {
		evalKey = cc.ReKeyGen(newKp.publicKey, kp.secretKey);
	} catch( std::exception& e ) {
		cout << e.what() << ", cannot proceed with PRE" << endl;
		return 0;
	}

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;

	if( beVerbose ) cout << "Running re-encryption" << endl;

	newCiphertext = cc.ReEncrypt(evalKey, ciphertext);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew2;

	if( beVerbose ) cout << "Running decryption of re-encrypted cipher" << endl;

	DecryptResult result1 = cc.Decrypt(newKp.secretKey,newCiphertext,&plaintextNew2,false);

	if (!result1.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	if( plaintext != plaintextNew2 ) {
		cout << "Mismatch on decryption of PRE ciphertext" << endl;
		return 1;
	}


	if( beVerbose ) cout << "Execution completed" << endl;

	return 0;
}
