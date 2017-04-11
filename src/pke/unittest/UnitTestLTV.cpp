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

class UnitTestLTV : public ::testing::Test {
protected:
	virtual void SetUp() {}

	virtual void TearDown() {}

public:
};

#ifdef OUT
/*Simple Encrypt-Decrypt check for ILVectorArray2n. The assumption is this test case is that everything with respect to lattice and math
* layers and cryptoparameters work. This test case is only testing if the resulting plaintext from an encrypt/decrypt returns the same
* plaintext
* The cyclotomic order is set 2048
*tower size is set to 3*/
TEST(UTLTVDCRT, ILVectorArray2n_Encrypt_Decrypt) {
  bool dbg_flag = false;

	usint m = 2048;

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");

	float stdDev = 4;

	usint size = 3;

	BytePlaintextEncoding ctxtd;

	vector<native64::BigBinaryInteger> moduli(size);

	vector<native64::BigBinaryInteger> rootsOfUnity(size);

	native64::BigBinaryInteger q("1");
	native64::BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	DEBUG("1");
	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, m, native64::BigBinaryInteger("4"), native64::BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
		DEBUG("2 i "<<i);
	}
	DEBUG("3");	

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );
	DEBUG("4");	

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

	UnitTestEncryption<ILVectorArray2n>(cc);
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
	cc.Enable(SHE);
	cc.Enable(PRE);

	UnitTestEncryption<ILVector2n>(cc);
}

TEST(UTLTV, Ops) {

	usint m = 2048;

	float stdDev = 4;

	BigBinaryInteger q("1");
	BigBinaryInteger temp;

	lbcrypto::NextQ(q, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(64, m, q.ToString(), RootOfUnity(m,q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(PRE);

	UnitTestDCRT<ILVector2n>(cc);
}

TEST(UTLTVDCRT, Ops_DCRT) {

	usint m = 2048;

	float stdDev = 4;

	usint size = 3;

	BytePlaintextEncoding ctxtd;

	vector<native64::BigBinaryInteger> moduli(size);

	vector<native64::BigBinaryInteger> rootsOfUnity(size);

	native64::BigBinaryInteger q("1");
	native64::BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < size; i++) {
		lbcrypto::NextQ(q, native64::BigBinaryInteger::TWO, m, native64::BigBinaryInteger("4"), native64::BigBinaryInteger("4"));
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
		modulus = modulus * BigBinaryInteger(moduli[i].ConvertToInt());
	}

	shared_ptr<ILDCRTParams> params( new ILDCRTParams(m, moduli, rootsOfUnity) );

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger(64));
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::getCryptoContextDCRT(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(PRE);

	UnitTestDCRT<ILVectorArray2n>(cc);
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

	float stdDev = 4;

	ILParams params(m, q, rootOfUnity);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(2, m, q.ToString(), RootOfUnity(m,q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);

//	// Initialize the public key containers.
//	LPKeyPair<ILVector2n> kp = cc.KeyGen();
//
//	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;
//
//	ciphertext = cc.Encrypt(kp.publicKey, plaintext);
//
//	BytePlaintextEncoding plaintextNew;
//
//	cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew);
//
//	EXPECT_EQ(plaintextNew, plaintext);

	UnitTestEncryption<ILVector2n>(cc);
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
	cc.Enable(SHE);

	UnitTestReEncryption<ILVector2n>(cc);
}
#endif
