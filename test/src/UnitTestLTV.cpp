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

#include "../../src/lib/encoding/byteencoding.h"
#include "../../src/lib/encoding/cryptoutility.h"

#include "../../src/lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestLTV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};


/*TEST(method_ILVectorArray2n, Encrypt_Decrypt) {

	usint m = 2048;

	ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	float stdDev = 4;

	usint size = 3;

	ByteArray ctxtd;

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus* moduli[i];
	}

	DiscreteGaussianGenerator dgg(stdDev);

	ILDCRTParams params(m, moduli, rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVectorArray2n> cipherText;
	cipherText.SetCryptoParameters(&cryptoParams);

	LPPublicKeyLTV<ILVectorArray2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVectorArray2n> sk(cryptoParams);

	size_t chunksize = ((m / 2) / 8);
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm(chunksize);
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	algorithm.KeyGen(&pk, &sk);	

	vector<Ciphertext<ILVectorArray2n>> ciphertext;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, plaintext, &ciphertext);

	ByteArray plaintextNew;

	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew, plaintext);
}

TEST(method_ILVector2n, Encrypt_Decrypt) {

	usint m = 2048;

	ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	float stdDev = 4;

	ByteArray ctxtd;
	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");
	
	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		
	DiscreteGaussianGenerator dgg(stdDev);

	ILParams params(m, q, RootOfUnity(m,q));

	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	Ciphertext<ILVector2n> cipherText;
	cipherText.SetCryptoParameters(&cryptoParams);

	LPPublicKeyLTV<ILVector2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVector2n> sk(cryptoParams);

	size_t chunksize = ((m / 2) / 8);
	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm(chunksize);
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	algorithm.KeyGen(&pk, &sk);

	vector<Ciphertext<ILVector2n>> ciphertext;

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext, &ciphertext);	

	ByteArray plaintextNew;

	CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext, &plaintextNew);  

	EXPECT_EQ(plaintextNew, plaintext);
}
*/



TEST(method_ILVector2n, PRE) {

	//usint m = 2048;
	//BigBinaryInteger modulus("268441601");
	//BigBinaryInteger rootOfUnity("16947867");
	//usint relWindow = 1;

	//ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	//cout << plaintext << endl;
	//float stdDev = 4;

	//ByteArray ctxtd;

	//DiscreteGaussianGenerator dgg(stdDev);

	//ILParams params(m, modulus,rootOfUnity);

	//LPCryptoParametersLTV<ILVector2n> cryptoParams;
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	//cryptoParams.SetDistributionParameter(stdDev);
	//cryptoParams.SetRelinWindow(1);
	//cryptoParams.SetElementParams(params);
	//cryptoParams.SetDiscreteGaussianGenerator(dgg);

	//Ciphertext<ILVector2n> cipherText;
	//cipherText.SetCryptoParameters(&cryptoParams);

	//LPPublicKeyLTV<ILVector2n> pk(cryptoParams);
	//LPPrivateKeyLTV<ILVector2n> sk(cryptoParams);

	//size_t chunksize = ((m / 2) / 8);
	//LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm(chunksize);
	//algorithm.Enable(ENCRYPTION);
	//algorithm.Enable(PRE);

	//algorithm.KeyGen(&pk, &sk);

	//vector<Ciphertext<ILVector2n>> ciphertext;

	//CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, plaintext, &ciphertext);

	//ByteArray plaintextNew;

	//CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext, &plaintextNew);

	//cout << plaintextNew << endl;

	//LPPublicKeyLTV<ILVector2n> newPK(cryptoParams);
	//LPPrivateKeyLTV<ILVector2n> newSK(cryptoParams);
	//
	//algorithm.KeyGen(&newPK, &newSK);	

	//LPEvalKeyLTV<ILVector2n> evalKey(cryptoParams);

	//algorithm.EvalKeyGen(newPK, sk, &evalKey);  

	//vector<Ciphertext<ILVector2n>> newCiphertext;

	//CryptoUtility<ILVector2n>::ReEncrypt(algorithm, evalKey, ciphertext, &newCiphertext); 

	//ByteArray plaintextNew2;

	//DecryptResult result1 = CryptoUtility<ILVector2n>::Decrypt(algorithm, newSK, newCiphertext, &plaintextNew2);  

	//EXPECT_EQ(plaintextNew, plaintextNew2);
}