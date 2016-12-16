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
TEST(UTBV, ILVector2n_bv_Encrypt_Decrypt) {

	usint m = 2048;
	//usint m = 8;
	BigBinaryInteger modulus("268441601");
	usint relWindow = 1;
	
	//lbcrypto::NextQ(modulus, BigBinaryInteger::TWO, m, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity((RootOfUnity(m, modulus)));

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	
	float stdDev = 4;

	std::vector<usint> vectorOfInts1 = { 1,0,1,0 };

	IntPlaintextEncoding intArray1(vectorOfInts1);

	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));

	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO); // Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);          // Set the noise parameters.
	cryptoParams.SetRelinWindow(relWindow);						   // Set the relinearization window
	cryptoParams.SetElementParams(params);                // Set the initialization parameters.


	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(PRE);

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), cc.GetElementParams());

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	//vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
		//	cc.Encrypt(kp.publicKey, intArray1,false);	// This is the core encryption operation.

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext =
		cc.Encrypt(kp.publicKey, plaintext, false);	// This is the core encryption operation.

	


	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;
	IntPlaintextEncoding intArrayNew;

	//DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew,false);
	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew, false);

	EXPECT_EQ(plaintextNew, plaintext);
	//EXPECT_EQ(intArrayNew, intArray1);

	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPKeyPair<ILVector2n> newKp = cc.KeyGen();


	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	shared_ptr<LPEvalKey<ILVector2n>> evalKey = cc.KeySwitchGen( kp.secretKey, newKp.secretKey);

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext = cc.ReEncrypt(evalKey, ciphertext);

	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew2;
	IntPlaintextEncoding intArrayNew2;

	//DecryptResult result1 = cc.Decrypt(newKp.secretKey, newCiphertext, &intArrayNew2,false);
	DecryptResult result1 = cc.Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2, false);
	/*ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();*/
	
	EXPECT_EQ(plaintextNew2, plaintext);
	//EXPECT_EQ(intArrayNew2, intArray1);
}


