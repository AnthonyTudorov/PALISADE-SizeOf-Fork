/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
12/22/2015 2:37PM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Gyana Sahu, grs22@njit.edu
Nishanth Pasham, np386@njit.edu
Description:
This code tests the transform feature of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "../include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"


#include "../../src/lib/crypto/cryptocontext.h"
#include "../../src/lib/utils/cryptocontexthelper.h"
#include "../../src/lib/crypto/cryptocontext.cpp"
#include "../../src/lib/utils/cryptocontexthelper.cpp"

#include "../../src/lib/encoding/packedintplaintextencoding.h"


#include "../../src/lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestBatching : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};


/*Simple Encrypt-Decrypt check for ILVectorArray2n. The assumption is this test case is that everything with respect to lattice and math
* layers and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*tower size is set to 3*/
TEST(UTLTVBATCHING, ILVector2n_Encrypt_Decrypt) {
	
	float stdDev = 4;

	usint m = 8;
	BigBinaryInteger modulus("268441601");
	BigBinaryInteger rootOfUnity("16947867");
	usint relWindow = 1;

	DiscreteGaussianGenerator dgg(stdDev);

	lbcrypto::NextQ(modulus, BigBinaryInteger(17), m, BigBinaryInteger("4"), BigBinaryInteger("4"));

	//Prepare for parameters.
	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));

	//Set crypto parametes
	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("17"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	std::vector<usint> vectorOfInts1 = { 8,5,16,9 };

	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	//Packing pliantext
	intArray1.Pack(cryptoParams.GetPlaintextModulus(), cryptoParams.GetElementParams()->GetCyclotomicOrder());

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), std::static_pointer_cast<ILParams>(cc.GetCryptoParameters()->GetElementParams()));


	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	///////////////////////////////////////////////////////////

	LPKeyPair<ILVector2n> kp = cc.KeyGen();


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	ciphertext = cc.Encrypt(kp.publicKey, intArray1, false);


	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	PackedIntPlaintextEncoding intArrayNew;

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);
	intArrayNew.Unpack(cryptoParams.GetPlaintextModulus(), cryptoParams.GetElementParams()->GetCyclotomicOrder());

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	EXPECT_EQ(intArrayNew, vectorOfInts1);

}


TEST(UTLTVBATCHING, ILVector2n_EVALADD) {

	float stdDev = 4;

	usint m = 8;
	BigBinaryInteger modulus("268441601");
	BigBinaryInteger rootOfUnity("16947867");
	usint relWindow = 1;

	DiscreteGaussianGenerator dgg(stdDev);

	lbcrypto::NextQ(modulus, BigBinaryInteger(17), m, BigBinaryInteger("4"), BigBinaryInteger("4"));

	//Prepare for parameters.
	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));

	//Set crypto parametes
	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("17"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	std::vector<usint> vectorOfInts1 = { 1,2,3,4 };

	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 4,3,2,1 };

	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	//Packing pliantext
	intArray1.Pack(cryptoParams.GetPlaintextModulus(), cryptoParams.GetElementParams()->GetCyclotomicOrder());

	intArray2.Pack(cryptoParams.GetPlaintextModulus(), cryptoParams.GetElementParams()->GetCyclotomicOrder());

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), std::static_pointer_cast<ILParams>(cc.GetCryptoParameters()->GetElementParams()));


	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	///////////////////////////////////////////////////////////

	LPKeyPair<ILVector2n> kp = cc.KeyGen();


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);


	////////////////////////////////////////////////////////////
	//EvalAdd Operation
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;
	ciphertextResult.insert(ciphertextResult.begin(), cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0)) );

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	PackedIntPlaintextEncoding intArrayNew;

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext1, &intArrayNew, false);
	intArrayNew.Unpack(cryptoParams.GetPlaintextModulus(), cryptoParams.GetElementParams()->GetCyclotomicOrder());

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	EXPECT_EQ(intArrayNew, vectorOfInts1);

}