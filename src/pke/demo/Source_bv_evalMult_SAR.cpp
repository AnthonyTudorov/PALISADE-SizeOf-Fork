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

#include "cryptocontext.h"
#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

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

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, rootOfUnity);
	std::cout << rootOfUnity << std::endl;

	BigBinaryInteger xroot(1);

	/*for (usint i = 0; i < 8; i++) {
		xroot = rootOfUnity*xroot;
		xroot = xroot.Mod(q);
		std::cout << xroot << std::endl;
	}*/


	ILVector2n x(params,Format::COEFFICIENT);
	x = { 1,2,3,4 };
	x.PrintValues();
	x.SwitchFormat();
	x.PrintValues();

	x.Shift(8);
	x.SwitchFormat();
	x.PrintValues();


	//	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(8);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cryptoParams.GetDiscreteGaussianGenerator(), params);
															//Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	std::vector<usint> vectorOfInts1 = { 4,1,3,2 };
	
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 3,0,0,0 };
	
	IntPlaintextEncoding intArray2(vectorOfInts2);
	

	LPPublicKeyEncryptionSchemeBV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(SHE);
	algorithm.Enable(LEVELEDSHE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext1;
	vector<Ciphertext<ILVector2n>> ciphertext2;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray1, &ciphertext1, false);

	ciphertext1.at(0).GetElements().at(0).Shift(2);
	ciphertext1.at(0).GetElements().at(1).Shift(2);

	sk.GetPrivateElement().Shift(2);

	IntPlaintextEncoding results;

	//CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext2, &results, false);

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext1, &results, false);

}
