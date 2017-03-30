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

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestBV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

/**Simple Encrypt-Decrypt check for BV scheme.
* This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*/
TEST(UTBVDCRT, ILVector2n_bv_Encrypt_Decrypt_DCRT) {

	usint m = 8;

	usint numOfTower = 3;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BigBinaryInteger q("50000");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
	}

	//Prepare for parameters.
	shared_ptr<ILDCRTParams> params(new ILDCRTParams(m, moduli, rootsOfUnity));

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("5"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);

	//CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(5, m, "modulus","rootOfUnity",8,stdDev);
	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(&cryptoParams, MODE::RLWE);
	cc.Enable(ENCRYPTION);


	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext =
		cc.Encrypt(kp.publicKey, intArray1,false); // This is the core encryption operation.


	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew,false);  // This is the core decryption operation.
	
	EXPECT_EQ(intArray1, intArrayNew);
}


TEST(UTBVDCRT, ILVector2n_bv_PRE_DCRT) {

	usint m = 8;

	usint numOfTower = 3;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BigBinaryInteger q("50000");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
	}

	//Prepare for parameters.
	shared_ptr<ILDCRTParams> params(new ILDCRTParams(m, moduli, rootsOfUnity));

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("2"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.

	std::vector<usint> vectorOfInts1 = { 1,0,1,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(&cryptoParams, MODE::RLWE);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);	
	cc.Enable(SHE);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext =
		cc.Encrypt(kp.publicKey, intArray1,false);

	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<ILVectorArray2n> newKp = cc.KeyGen();

	/*shared_ptr<LPEvalKey<ILVectorArray2n>> evalKey =
		cc.ReKeyGen(newKp.secretKey, kp.secretKey);*/
	shared_ptr<LPEvalKey<ILVectorArray2n>> evalKey =
		cc.ReKeyGen(newKp.secretKey, kp.secretKey);

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> newCiphertext =
		cc.ReEncrypt(evalKey, ciphertext);
																			

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding intArrayNew;


	DecryptResult result1 = cc.Decrypt(newKp.secretKey, newCiphertext, &intArrayNew,false);


	EXPECT_EQ(intArray1, intArrayNew);
}

TEST(UTBVDCRT, ILVector2n_bv_EVALADD_DCRT) {

	usint m = 8;

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

	//Prepare for parameters.
	shared_ptr<ILDCRTParams> params(new ILDCRTParams(m, moduli, rootsOfUnity));

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger(13));  	// Set plaintext modulus.
																//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(1);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(&cryptoParams, MODE::RLWE);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	std::vector<usint> vectorOfInts1(4);
	vectorOfInts1 = { 2,3,1,4 };
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2(4);
	vectorOfInts2 = { 3,6,3,1 };
	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected(4);
	vectorOfIntsExpected = { 5,9,4,5 };
	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	//LPAlgorithmLTV<ILVector2n> algorithm;

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext1 =
		cc.Encrypt(kp.publicKey, intArray1,false);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext2 =
		cc.Encrypt(kp.publicKey, intArray2,false);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> cResult;

	cResult.insert( cResult.begin(), cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0)));

	IntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, cResult, &results,false);	

	EXPECT_EQ(intArrayExpected, results);
}


TEST(UTBVDCRT, ILVector2n_bv_EVALMULT) {

	usint m = 8;

	float stdDev = 4;

	BigBinaryInteger q("21990232");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	shared_ptr<ILParams> params(new ILParams(m, q, rootOfUnity));

	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(8);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(&cryptoParams, MODE::RLWE);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);


	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 3,0,0,0 };

	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 2,0,0,0 };

	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1 =
		cc.Encrypt(kp.publicKey, intArray1,false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2 =
		cc.Encrypt(kp.publicKey, intArray2,false);

	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> cResult;

	cResult.insert(cResult.begin(), cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0)));


	IntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, cResult, &results,false);

	EXPECT_EQ(intArrayExpected, results);

}


TEST(UTBVDCRT, ILVector2n_bv_EVALMULT_DCRT) {

	usint init_m = 8;

	float init_stdDev = 4;

	usint init_size = 5;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("21990232");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];
	}

	shared_ptr<ILDCRTParams> params(new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity));

	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(init_stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 2,0,0,0 };
	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 3,0,0,0 };
	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);


	// Initialize the public key containers.
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();


	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext1 =
		cc.Encrypt(kp.publicKey, intArray1,false);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext2 =
		cc.Encrypt(kp.publicKey, intArray2,false);

	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> cResult;

	cResult.insert(cResult.begin(), cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0)) );

	IntPlaintextEncoding results;

	cc.Decrypt(kp.secretKey, cResult, &results,false);

	EXPECT_EQ(intArrayExpected, results);

}


TEST(UTBVDCRT, ILVector2n_bv_DCRT_MODREDUCE) {

	usint m = 8;

	usint numOfTower = 3;

	float stdDev = 4;

	std::vector<BigBinaryInteger> moduli(numOfTower);

	std::vector<BigBinaryInteger> rootsOfUnity(numOfTower);

	BigBinaryInteger q("50000");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus* moduli[j];
		//std::cout << "modulus is: " << moduli[j] << std::endl;
		//std::cout << "rootsOfUnity is: " << rootsOfUnity[j] << std::endl;
	}


	//std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	//Prepare for parameters.
	shared_ptr<ILDCRTParams> params(new ILDCRTParams(m, moduli, rootsOfUnity));

	//Set crypto parametes
	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger("5"));  	// Set plaintext modulus.
																//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(8);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	// Initialize the public key containers.
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;

	std::vector<usint> vectorOfInts1 = { 4,1,2,3 };

	IntPlaintextEncoding intArray1(vectorOfInts1);


	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	// Begin the initial encryption operation.
	//cout<<"\n"<<"original plaintext: "<< intArray1 <<"\n"<<endl;

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext =
		cc.Encrypt(kp.publicKey, intArray1,false);


	IntPlaintextEncoding intArrayNew;

	ciphertext = cc.ModReduce(ciphertext);

	//drop a tower from the secret key
	
	auto skEl(kp.secretKey->GetPrivateElement());
	skEl.DropLastElement();
	kp.secretKey->SetPrivateElement(skEl);

	cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew,false);

	EXPECT_EQ(intArray1, intArrayNew);

}

/*
TEST(UTBVDCRT, ILVector2n_bv_DCRT_MULT_MODREDUCE) {//TO ADD MODREDUCE

	usint init_m = 8;

	float init_stdDev = 4;

	usint init_size = 3;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("2199023282348389495048590");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];
	}

	shared_ptr<ILDCRTParams> params(new ILDCRTParams(init_m, init_moduli, init_rootsOfUnity));


	LPCryptoParametersBV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(init_stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(1);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	//Initialize the public key containers.
	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	std::vector<usint> vectorOfInts1 = { 4,0,0,0 };
	IntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2 = { 2,0,0,0 };
	IntPlaintextEncoding intArray2(vectorOfInts2);

	std::vector<usint> vectorOfIntsExpected = { 3,0,0,0 };
	IntPlaintextEncoding intArrayExpected(vectorOfIntsExpected);

	
	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext1 =
		cc.Encrypt(kp.publicKey, intArray1,false);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext2 =
		cc.Encrypt(kp.publicKey, intArray2,false);

	cc.EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> cResult;

	cResult.insert( cResult.begin() , cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0)) );

	cResult = cc.ModReduce(cResult);

	IntPlaintextEncoding results;

	auto skEl(kp.secretKey->GetPrivateElement());
	skEl.DropLastElement();
	kp.secretKey->SetPrivateElement(skEl);

	cc.Decrypt(kp.secretKey, cResult, &results, false);

	EXPECT_EQ(intArrayExpected, results);
}
*/




