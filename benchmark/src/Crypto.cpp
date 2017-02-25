//Hi Level Execution/Demonstration with Benchmarking
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
		Dr. David Bruce Cousins dcousins@bbn.com
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

Additionally we excercise the gnu benchmark libraryh
License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#define _USE_MATH_DEFINES
#include "benchmark/benchmark_api.h"


#include <iostream>
#include <fstream>
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"

using namespace std;
using namespace lbcrypto;

#include "BBVhelper.h"
#include "ElementParmsHelper.h"
#include "EncryptHelper.h"

void BM_keygen(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		ChineseRemainderTransformFTT::GetInstance().PreCompute(cc.GetElementParams()->GetRootOfUnity(),
				cc.GetElementParams()->GetCyclotomicOrder(),
				cc.GetElementParams()->GetModulus());
		ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		LPKeyPair<ILVector2n> kp = cc.KeyGen();
	}
}

BENCHMARK_PARMS(BM_keygen)

#ifdef OUT
static void BM_SOURCE(benchmark::State& state) {

	// std::cout << "Relinearization window : " << std::endl;
	// std::cout << "0 (r = 1), 1 (r = 2), 2 (r = 4), 3 (r = 8), 4 (r = 16): [0] ";

	int input = 0;
	// std::cin >> input;
	// //cleans up the buffer
	// cin.ignore();

	// if ((input<0) || (input>4))
	// 	input = 0;

       
	while (state.KeepRunning()) {
	  ////NTRUPRE is where the core functionality is provided.
	  NTRUPRE(state.range_x());

	  //std::cin.get();
	  ChineseRemainderTransformFTT::GetInstance().Destroy();
	  NumberTheoreticTransform::GetInstance().Destroy();
	}

	return ;
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
void NTRUPRE(int input) {

	//Set element params

	// Remove the comments on the following to use a low-security, highly efficient parameterization for integration and debugging purposes.
	/*
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	BytePlaintextEncoding plaintext = "N";
	*/

	// The comments below provide a high-security parameterization for prototype use.  If this code were verified/certified for high-security applications, we would say that the following parameters would be appropriate for "production" use.
	//usint m = 2048;
	//BigBinaryInteger modulus("8590983169");
	//BigBinaryInteger rootOfUnity("4810681236");
	//BytePlaintextEncoding plaintext = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";

	SecureParams const SECURE_PARAMS[] = {
		{ 2048, ("268441601"), ("16947867"), 1 }, //r = 1
		{ 2048, ("536881153"), ("267934765"), 2 }, // r = 2
		{ 2048, ("1073750017"), ("180790047"), 4 },  // r = 4
		{ 2048, ("8589987841"), ("2678760785"), 8 }, //r = 8
		{ 4096, ("2199023288321"), ("1858080237421"), 16 }  // r= 16
	};

	usint m = SECURE_PARAMS[input].m;
	string modulus(SECURE_PARAMS[input].modulus);
	string rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	usint relWindow = SECURE_PARAMS[input].relinWindow;

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	float stdDev = 4;

	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	//Set crypto parametes

	CryptoContext<ILVector2n> cc =  CryptoContextFactory<ILVector2n>::genCryptoContextLTV(
			/* plaintextmodulus */ 2,
			/* ringdim */ m,
			modulus,
			rootOfUnity,
			relWindow,
			stdDev);

	//This code is run only when performing execution time measurements
	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(BigBinaryInteger(rootOfUnity), m, BigBinaryInteger(modulus));

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout<<"Key generation failed!"<<std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	// Begin the initial encryption operation.

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	ciphertext = cc.Encrypt(kp.publicKey,plaintext);

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	DecryptResult result = cc.Decrypt(kp.secretKey,ciphertext,&plaintextNew);

	if (!result.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<ILVector2n> newKp;

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	start = currentDateTime();

	newKp = cc.KeyGen();

	finish = currentDateTime();
	diff = finish - start;

	cout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	shared_ptr<LPEvalKey<ILVector2n>> evalKey;

	start = currentDateTime();

	evalKey = cc.ReKeyGen(newKp.publicKey, kp.secretKey);  // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;

	std::cout <<"\n"<< "Running re-encryption..." << std::endl;

	start = currentDateTime();

	newCiphertext = cc.ReEncrypt(evalKey, ciphertext);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;


	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew2;

	std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	start = currentDateTime();

	DecryptResult result1 = cc.Decrypt(newKp.secretKey,newCiphertext,&plaintextNew2);

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

}

BASIC_BENCHMARK_TEST(BM_SOURCE); // runs the benchmark over the range of input
#endif

BENCHMARK_MAIN()

