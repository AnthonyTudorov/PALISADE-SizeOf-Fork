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

#include "../../src/lib/encoding/byteplaintextencoding.h"
#include "../../src/lib/encoding/intplaintextencoding.h"


#include "../../src/lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

class UnitTestLTV : public ::testing::Test {
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
TEST(UTLTV, ILVectorArray2n_Encrypt_Decrypt) {
  bool dbg_flag = false;

	usint m = 2048;

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	float stdDev = 4;

	usint size = 3;

	BytePlaintextEncoding ctxtd;

	vector<BigBinaryInteger> moduli(size);

	vector<BigBinaryInteger> rootsOfUnity(size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	DEBUG("1");
	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus* moduli[i];
		DEBUG("2 i "<<i);
	}
	DEBUG("3");	
	DiscreteGaussianGenerator dgg(stdDev);

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );
	DEBUG("4");	

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	LPKeyPair<ILVectorArray2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVectorArray2n>>> ciphertext =
		cc.Encrypt(kp.publicKey, plaintext);

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

	DEBUG("11");	
	EXPECT_EQ(plaintextNew, plaintext);
	DEBUG("Done");	
}

/*Simple Encrypt-Decrypt check for ILVector2n. The assumption is this test case is that everything with respect to lattice and math
* layers and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*/
TEST(UTLTV, ILVector2n_Encrypt_Decrypt) {

	usint m = 2048;

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	
	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m, q.ToString(), RootOfUnity(m,q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(RootOfUnity(m,q), m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, plaintext);

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew, plaintext);
	ILVector2n::DestroyPreComputedSamples();
}

/*Simple Encrypt-Decrypt check for ILVector2n with a short ring dimension. The assumption is this test case is that everything with respect to lattice and math
* layers and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set to 8
*/
TEST(UTLTV, ILVector2n_Encrypt_Decrypt_Short_Ring) {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	BytePlaintextEncoding plaintext = "N";

	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	float stdDev = 4;

	//BytePlaintextEncoding ctxtd;
	//BigBinaryInteger q("1");
	//BigBinaryInteger temp;

	//lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));

	DiscreteGaussianGenerator dgg(stdDev);
	//BigBinaryInteger rootOfUnity(RootOfUnity(m, q));
	ILParams params(m, q, rootOfUnity);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m, q.ToString(), RootOfUnity(m,q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(RootOfUnity(m,q), m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	ciphertext = cc.Encrypt(kp.publicKey, plaintext);

	BytePlaintextEncoding plaintextNew;

	cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew, plaintext);
	ILVector2n::DestroyPreComputedSamples();
}

/*Simple Proxy re-encryption test for ILVector2n. The assumption is this test case is that everything with respect to the lattice
* layer and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
* The relinwindow is set to 1 and the modulus and root of unity are precomputed values that satisfy PRE conditions
*/
TEST(UTLTV, ILVector2n_Encrypt_Decrypt_PRE) {

	usint m = 2048;
	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	float stdDev = 4;

	BytePlaintextEncoding ctxtd;

	BigBinaryInteger q("268441601");
	BigBinaryInteger rootOfUnity("16947867");

	//This code is run only when performing execution time measurements

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m, q.ToString(), rootOfUnity.ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
		cc.Encrypt(kp.publicKey, plaintext);

	BytePlaintextEncoding plaintextNew;
	cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);

	EXPECT_EQ(plaintextNew, plaintext);
	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<ILVector2n> newKp = cc.KeyGen();

	shared_ptr<LPEvalKey<ILVector2n>> evalKey =
			cc.ReKeyGen(newKp.publicKey, kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext =
			cc.ReEncrypt(evalKey, ciphertext);

	BytePlaintextEncoding plaintextNew2;

	DecryptResult result1 = cc.Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2);

	EXPECT_EQ(plaintextNew2, plaintext);
	ILVector2n::DestroyPreComputedSamples();

}

TEST(UTLTV, ILVector2n_IntPlaintextEncoding_Encrypt_Decrypt) {

	usint m = 16;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("40"), BigBinaryInteger("4"));

	BigBinaryInteger rootOfUnity(RootOfUnity(m, q));

	std::vector<usint> vectorOfInts = {1,0,1,0,1,0,1,0};
	IntPlaintextEncoding intArray(vectorOfInts);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m, q.ToString(), rootOfUnity.ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(LEVELEDSHE);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, q);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
			cc.Encrypt(kp.publicKey, intArray);

	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew);

	EXPECT_EQ(intArray, intArrayNew);

	ILVector2n::DestroyPreComputedSamples();

}

