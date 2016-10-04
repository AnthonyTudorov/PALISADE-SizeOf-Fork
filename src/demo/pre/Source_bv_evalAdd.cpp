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
void EncryptionTest();
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
	EncryptionTest();
	//NTRUPRE(3);
	
	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}




void EncryptionTest() {
	
	usint m = 16;
	

	usint numOfTower = 2;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BytePlaintextEncoding ctxtd;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
	}


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	DiscreteGaussianGenerator dgg(stdDev);

	//Prepare for parameters.
	ILDCRTParams params(m, moduli, rootsOfUnity);

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger(13));  	// Set plaintext modulus.
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(1);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootsOfUnity, m, moduli);

	//Precomputations for DGG
	//ILVector2n::PreComputeDggSamples(dgg, params);


	// Initialize the public key containers.
	LPPublicKey<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKey<ILVectorArray2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1(8);
	vectorOfInts1.at(0) = 2;
	vectorOfInts1.at(1) = 3;
	vectorOfInts1.at(2) = 1;
	vectorOfInts1.at(3) = 4;
	std::fill(vectorOfInts1.begin() + 4, vectorOfInts1.end(), 0);
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(8);
	vectorOfInts2.at(0) = 3;
	vectorOfInts2.at(1) = 6;
	vectorOfInts2.at(2) = 3;
	vectorOfInts2.at(3) = 1;
	IntPlaintextEncoding intArray2(vectorOfInts2);
	std::fill(vectorOfInts2.begin() + 4, vectorOfInts2.end(), 0);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;


	LPPublicKeyEncryptionSchemeBV<ILVectorArray2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);

	bool successKeyGen = false;

	std::cout <<"\n" <<  "Running key generation..." << std::endl;


	successKeyGen = algorithm.KeyGen(&pk,&sk);	// This is the core function call that generates the keys.


	vector<Ciphertext<ILVectorArray2n>> ciphertext1;
	vector<Ciphertext<ILVectorArray2n>> ciphertext2;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, intArray2, &ciphertext2, false);

	Ciphertext<ILVectorArray2n> cResult(ciphertext1.at(0));

	algorithm.EvalAdd(ciphertext1.at(0), ciphertext2.at(0), &cResult);

	
	vector<Ciphertext<ILVectorArray2n>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	IntPlaintextEncoding results;
	
	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertextResults, &results, false);

}
