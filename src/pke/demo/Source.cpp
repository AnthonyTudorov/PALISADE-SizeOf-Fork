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


int main(int argc, char *argv[])
{
	string parmSetName;
	bool beVerbose = false;
	bool haveName = false;

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

	auto parmfind = CryptoContextParameterSets.find(parmSetName);
	if( parmfind == CryptoContextParameterSets.end() ) {
		cout << "Parameter set " << parmSetName << " is not a recognized name" << endl;
		haveName = false;
	}

	if( !haveName ) {
		// print out available sets
		cout << "Available crypto parameter sets are:" << endl;
		CryptoContextHelper<ILVector2n>::printAllParmSetNames(cout);
		return 1;
	}

	if( beVerbose ) {
		CryptoContextHelper<ILVector2n>::printParmSet(cout, parmSetName);
	}

	// Parameter set selected

	// Construct a crypto context for this parameter set

	if( beVerbose ) cout << "Initializing crypto system" << endl;

	CryptoContext<ILVector2n> cc = CryptoContextHelper<ILVector2n>::getNewContext(parmSetName);
	
	// enable features
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	// create initial plaintext
	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

#ifdef OUT
	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), std::static_pointer_cast<ILParams>(cc.GetCryptoParameters()->GetElementParams()));
#endif

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
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	if( beVerbose ) cout << "Running encryption" << endl;

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

	shared_ptr<LPEvalKey<ILVector2n>> evalKey = cc.ReKeyGen(newKp.publicKey, kp.secretKey);

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
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

	//	ChineseRemainderTransformFTT::GetInstance().Destroy();
	//	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}
