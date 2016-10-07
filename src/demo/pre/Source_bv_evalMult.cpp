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
	
	usint m = 8;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4000"), BigBinaryInteger("40000"));
	DiscreteGaussianGenerator dgg(stdDev);
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, RootOfUnity(m, q));

	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, params);

	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(16);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);         // Create the noise generator

															//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };
	
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 0,0,3,0 };
	
	IntPlaintextEncoding intArray2(vectorOfInts2);
	

	LPPublicKeyEncryptionSchemeBV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext1;
	vector<Ciphertext<ILVector2n>> ciphertext2;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);

	

	Ciphertext<ILVector2n> cResult(ciphertext1.at(0));

	LPEvalKeyRelin<ILVector2n> keySwitchHint(cryptoParams);	

	algorithm.QuadraticEvalMultKeyGen(sk, sk, &keySwitchHint);

	algorithm.EvalMult(ciphertext1.at(0), ciphertext2.at(0), keySwitchHint, &cResult);

	vector<Ciphertext<ILVector2n>> ciphertextResults(1);

	ciphertextResults.at(0) = cResult;

	IntPlaintextEncoding results;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertextResults, &results, false);

}
