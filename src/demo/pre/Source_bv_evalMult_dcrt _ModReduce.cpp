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

#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/utils/cryptoutility.h"
#include "../../lib/encoding/intplaintextencoding.h"

#include "../../lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;
void EvalMultTest();
//double currentDateTime();

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

#include <iterator>

int main() {

	////NTRUPRE is where the core functionality is provided.
	EvalMultTest();
	//NTRUPRE(3);
	
	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}




void EvalMultTest() {
	
	usint init_m = 8;

	float init_stdDev = 4;

	usint init_size = 3;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("2199023288321");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];
		cout << "modulus: " << init_moduli[i] << endl;
		cout << "root: " << init_rootsOfUnity[i] << endl;
	}

	DiscreteGaussianGenerator dgg(init_stdDev);
	ILDCRTParams params(init_m, init_moduli, init_rootsOfUnity);
	

	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG

	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(init_stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

															//Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };
	
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 2,0,0,0 };
	
	IntPlaintextEncoding intArray2(vectorOfInts2);
	

	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVectorArray2n>> ciphertext1;
	vector<Ciphertext<ILVectorArray2n>> ciphertext2;
	vector<Ciphertext<ILVectorArray2n>> ciphertextResult(1);

	ciphertextResult.at(0).SetCryptoParameters(&cryptoParams);


	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);

	//Ciphertext<ILVectorArray2n> cResult(ciphertext1.at(0));

	LPEvalKeyRelin<ILVectorArray2n> keySwitchHint(cryptoParams);

	algorithm.QuadraticEvalMultKeyGen(sk, sk, &keySwitchHint);


	algorithm.EvalMult(ciphertext1.at(0), ciphertext2.at(0), keySwitchHint, &ciphertextResult.at(0));

	//CryptoUtility<ILVectorArray2n>::ModReduce(algorithm,&ciphertextResult);


	IntPlaintextEncoding results;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertextResult, &results, false);

}
