/*
 * helperUnitTestDCRT.cpp
 *
 *  Created on: Apr 4, 2017
 *      Author: gerardryan
 */


#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"


#include "../lib/cryptocontext.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"


#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

template<class Element>
void UnitTestDCRT(const CryptoContext<Element>& cc) {

	std::vector<uint32_t> vectorOfInts1 = { 1,0,3,1,0,1,2,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 2,1,3,2,2,1,3,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfIntsAdd = { 3,1,6,3,2,2,5,1 };
	IntPlaintextEncoding plaintextAdd(vectorOfIntsAdd);

	std::vector<uint32_t> vectorOfIntsSub = { 63,63,0,63,62,0,63,1 };
	IntPlaintextEncoding plaintextSub(vectorOfIntsSub);

	std::vector<uint32_t> vectorOfIntsMult = { 2, 1, 9, 7, 12, 12, 16, 12, 19, 12, 7, 7, 7, 3 };
	//std::vector<uint32_t> vectorOfIntsMult = { 47, 53, 2, 0, 5, 9, 16, 12 };
	IntPlaintextEncoding plaintextMult(vectorOfIntsMult);

//	if( cc.GetCyclotomicOrder() != 16 || cc.GetCryptoParameters()->GetPlaintextModulus().ConvertToInt() != 64 ) {
//		GTEST_FAIL() << "UnitTestDCRT requires m=16 and ptm=64";
//		return;
//	}

	{
		// EVAL ADD
		IntPlaintextEncoding intArray1(vectorOfInts1);

		IntPlaintextEncoding intArray2(vectorOfInts2);

		IntPlaintextEncoding intArrayExpected(vectorOfIntsAdd);

		////////////////////////////////////////////////////////////
		//Perform the key generation operation.
		////////////////////////////////////////////////////////////
		LPKeyPair<Element> kp = cc.KeyGen();

		vector<shared_ptr<Ciphertext<Element>>> ciphertext1 =
				cc.Encrypt(kp.publicKey, intArray1,false);

		vector<shared_ptr<Ciphertext<Element>>> ciphertext2 =
				cc.Encrypt(kp.publicKey, intArray2,false);

		vector<shared_ptr<Ciphertext<Element>>> cResult;

		cResult.insert( cResult.begin(), cc.EvalAdd(ciphertext1.at(0), ciphertext2.at(0)));

		IntPlaintextEncoding results;

		cc.Decrypt(kp.secretKey, cResult, &results,false);

		results.resize(intArrayExpected.size());

		EXPECT_EQ(intArrayExpected, results) << "EvalAdd fails";
	}

	{
		// EVAL MULT
		IntPlaintextEncoding intArray1(vectorOfInts1);

		IntPlaintextEncoding intArray2(vectorOfInts2);

		IntPlaintextEncoding intArrayExpected(vectorOfIntsMult);

		// Initialize the public key containers.
		LPKeyPair<Element> kp = cc.KeyGen();

		vector<shared_ptr<Ciphertext<Element>>> ciphertext1 =
			cc.Encrypt(kp.publicKey, intArray1,false);

		vector<shared_ptr<Ciphertext<Element>>> ciphertext2 =
			cc.Encrypt(kp.publicKey, intArray2,false);

		cc.EvalMultKeyGen(kp.secretKey);

		vector<shared_ptr<Ciphertext<Element>>> cResult;

		cResult.insert(cResult.begin(), cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0)));

		IntPlaintextEncoding results;

		cc.Decrypt(kp.secretKey, cResult, &results,false);

		results.resize(intArrayExpected.size());

		EXPECT_EQ(intArrayExpected, results) << "EvalMult fails";

	}

}

template void UnitTestDCRT<ILVector2n>(const CryptoContext<ILVector2n>& cc);
template void UnitTestDCRT<ILVectorArray2n>(const CryptoContext<ILVectorArray2n>& cc);


