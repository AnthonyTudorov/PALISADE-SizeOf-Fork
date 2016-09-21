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
	This code exercises the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.
	In this code we:
		- Generate a key pair.
		- Encrypt a string of data.
		- Decrypt the data.
		- Generate a new key pair.
		- Generate a proxy re-encryption key.
		- Re-Encrypt the encrypted data.
		- Decrypt the re-encrypted data.
	We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor and may be closer to AES-256.

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
#include <iterator>

#include "../lib/palisade.h"
#include "../lib/palisadespace.h"

#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/debug.h"
#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/utils/cryptoutility.h"

using namespace lbcrypto;

void NTRUPRE(CryptoContext<ILVector2n> *ctx, bool);

#include "../../lib/utils/serializablehelper.h"

//#include "testJson.h"
//#include "testJson.cpp"

using namespace std;
using namespace lbcrypto;

void usage()
{
	cout << "args are:" << endl;
	cout << "-dojson : includes the json tests" << endl;
	cout << "an arg not beginning with a - is taken as a filename of parameters" << endl;
}

int
main(int argc, char *argv[])
{
	bool	doJson = false;

	string filename = "src/demo/pre/PalisadeCryptoContext.parms";

	while( argc-- > 1 ) {
		string arg(*++argv);

		if( arg == "-dojson" )
			doJson = true;
		else if( arg == "-help" || arg == "-?" ) {
			usage();
			return 0;
		}
		else if( arg[0] == '-' ) {
			usage();
			return(0);
		}

		else filename = arg;
	}

	std::cout << "Choose parameter set: ";
	CryptoContextHelper<ILVector2n>::printAllParmSetNames(std::cout, filename);

	string input;
	std::cin >> input;

	CryptoContext<ILVector2n> *ctx = CryptoContextHelper<ILVector2n>::getNewContext(filename, input);
	if( ctx == 0 ) {
		cout << "Error on " << input << endl;
		return 0;
	}

	NTRUPRE(ctx, doJson);

	delete ctx;

	//	ChineseRemainderTransformFTT::GetInstance().Destroy();
	//	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}

//////////////////////////////////////////////////////////////////////
//	NTRUPRE is where the core functionality is provided.
//	In this code we:
//		- Generate a key pair.
//		- Encrypt a string of data.
//		- Decrypt the data.
//		- Generate a new key pair.
//		- Generate a proxy re-encryption key.
//		- Re-Encrypt the encrypted data.
//		- Decrypt the re-encrypted data.
//////////////////////////////////////////////////////////////////////
//	We provide two different paramet settings.
//	The low-security, highly efficient settings are commented out.
//	The high-security, less efficient settings are enabled by default.
//////////////////////////////////////////////////////////////////////

void
NTRUPRE(CryptoContext<ILVector2n> *ctx, bool doJson) {

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");


	ofstream fout;
	fout.open ("output.txt");


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	double diff, start, finish;

	start = currentDateTime();

	//This code is run only when performing execution time measurements

	//	//Precomputations for FTT
	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);
	//
	//	//Precomputations for DGG
	//	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Precomputation time: " << "\t" << diff << " ms" << endl;
	fout << "Precomputation time: " << "\t" << diff << " ms" << endl;

	// Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(*ctx->getParams());
	LPPrivateKey<ILVector2n> sk(*ctx->getParams());

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	bool successKeyGen=false;

	std::cout <<"\n" <<  "Running key generation..." << std::endl;

	start = currentDateTime();

	successKeyGen = CryptoUtility<ILVector2n>::KeyGen(*ctx->getAlgorithm(),&pk,&sk);	// This is the core function call that generates the keys.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	//fout<< currentDateTime()  << " pk = "<<pk.GetPublicElement().GetValues()<<endl;
	//fout<< currentDateTime()  << " sk = "<<sk.GetPrivateElement().GetValues()<<endl;

	if (!successKeyGen) {
		std::cout<<"Key generation failed!"<<std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	// Begin the initial encryption operation.
	cout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;
	fout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;

	vector<Ciphertext<ILVector2n>> ciphertext;

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	CryptoUtility<ILVector2n>::Encrypt(*ctx->getAlgorithm(),pk,plaintext,&ciphertext);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	std::cout <<"\n"<< "Running decryption..." << std::endl;

	start = currentDateTime();

	DecryptResult result = CryptoUtility<ILVector2n>::Decrypt(*ctx->getAlgorithm(),sk,ciphertext,&plaintextNew);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;

	//cout << "ciphertext at" << ciphertext.GetIndexAt(2);

	if (!result.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPPublicKey<ILVector2n> newPK(*ctx->getParams());
	LPPrivateKey<ILVector2n> newSK(*ctx->getParams());

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	start = currentDateTime();

	successKeyGen = CryptoUtility<ILVector2n>::KeyGen(*ctx->getAlgorithm(),&newPK,&newSK);	// This is the same core key generation operation.

	finish = currentDateTime();
	diff = finish - start;

	cout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	LPEvalKeyNTRURelin<ILVector2n> evalKey(*ctx->getParams());

	start = currentDateTime();

	CryptoUtility<ILVector2n>::ReKeyGen(*ctx->getAlgorithm(), newPK, sk, &evalKey);  // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<Ciphertext<ILVector2n>> newCiphertext;

	std::cout <<"\n"<< "Running re-encryption..." << std::endl;

	start = currentDateTime();

	CryptoUtility<ILVector2n>::ReEncrypt(*ctx->getAlgorithm(), evalKey, ciphertext, &newCiphertext);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew2;

	std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	start = currentDateTime();

	DecryptResult result1 = CryptoUtility<ILVector2n>::Decrypt(*ctx->getAlgorithm(),newSK,newCiphertext,&plaintextNew2);  // This is the core decryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;

	if (!result1.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	std::cout << "Execution completed." << std::endl;

	BytePlaintextEncoding newPlaintext("1) SERIALIZE CRYPTO-OBJS TO FILE AS NESTED JSON STRUCTURES\n2) DESERIALIZE JSON FILES INTO CRYPTO-OBJS USED FOR CRYPTO-APIS\n3) Profit!!!!!");

	cout << "Original Plaintext: " << endl;
	cout << newPlaintext << endl;

//	if( doJson ) {
//		TestJsonParms<ILVector2n>	tjp;
//		tjp.ctx = ctx;
//		tjp.pk = &pk;
//		tjp.sk = &sk;
//		tjp.evalKey = &evalKey;
//		tjp.newSK = &newSK;
//
//		testJson<ILVector2n>("LTV", newPlaintext, &tjp);
//	}

	fout.close();
}


