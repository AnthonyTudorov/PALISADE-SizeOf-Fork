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
Hadi Sajjadpour, ss2959@njit.edu
Description:
This code tests the transform feature of the PALISADE lattice encryption library.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This file tests the following
EvalAdd
EvalMult
ComposedEvalMult
LevelReduction

ModReduce, RingReduce and KeySwitch Hint will be in UnitTestSHE.cpp

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
#include "../../src/lib/crypto/ciphertext.h"
#include "../../src/lib/crypto/ciphertext.cpp"


#include "../../src/lib/encoding/byteplaintextencoding.h"
#include "../../src/lib/encoding/intplaintextencoding.h"

#include "../../src/lib/utils/cryptoutility.h"

#include "../../src/lib/utils/debug.h"
#include <cmath>


using namespace std;
using namespace lbcrypto;

// A new one of these is created for each test
class UnitTestSHEAdvanced : public testing::Test
{
public:
	UnitTestSHEAdvanced() {}
	
	virtual void SetUp()
	{

		

	}

	virtual void TearDown()
	{
	}
};

/*Testing EvalAdd for both ILVector2n and ILVectorArray2n
* EvalAdd is tested in both coefficient and evaluation domains
*/
TEST_F(UnitTestSHEAdvanced, test_eval_add) {
	//parameter setup
	usint m = 16;
	Ciphertext<ILVector2n> cipher1_single_crt;
	Ciphertext<ILVector2n> cipher2_single_crt;

	Ciphertext<ILVectorArray2n> cipher1_dcrt;
	Ciphertext<ILVectorArray2n> cipher2_dcrt;

	vector<ILVector2n> ilvectors_dcrt_vector_1;
	vector<ILVector2n> ilvectors_dcrt_vector_2;
	vector<ILVector2n> ilvectors_single_crt_vector;

	//q1 and q2 are precalculated prime modulis

	BigBinaryInteger q1("17729");
	BigBinaryInteger rootOfUnity1(RootOfUnity(m, q1));

	BigBinaryInteger q2("17761");
	BigBinaryInteger rootOfUnity2(RootOfUnity(m, q2));

	//setting up two parameters. ilparams2 will be only used for double-crt
	ILParams ilParams1(m, q1, rootOfUnity1);
	ILParams ilParams2(m, q2, rootOfUnity2);

	//construcing an ILVector2n, this 
	ILVector2n ilv_single_crt1_dcrt1(ilParams1); // Used for both single and double crt
	BigBinaryInteger modulus(ilParams1.GetModulus());
	BigBinaryVector bbv1(m / 2, modulus);
	bbv1.SetValAtIndex(0, "4");
	bbv1.SetValAtIndex(1, "21323");
	bbv1.SetValAtIndex(2, "2");
	bbv1.SetValAtIndex(3, "0");
	bbv1.SetValAtIndex(4, "12301");
	bbv1.SetValAtIndex(5, "1");
	bbv1.SetValAtIndex(6, "0");
	bbv1.SetValAtIndex(7, "6");
	ilv_single_crt1_dcrt1.SetValues(bbv1, Format::COEFFICIENT);

	ILVector2n ilv_single_crt2(ilParams1);
	BigBinaryVector bbv2(m / 2, ilParams1.GetModulus());
	bbv2.SetValAtIndex(0, "1");
	bbv2.SetValAtIndex(1, "3");
	bbv2.SetValAtIndex(2, "2");
	bbv2.SetValAtIndex(3, "0");
	bbv2.SetValAtIndex(4, "17730");
	bbv2.SetValAtIndex(5, "32");
	bbv2.SetValAtIndex(6, "1");
	bbv2.SetValAtIndex(7, "0");
	ilv_single_crt2.SetValues(bbv2, Format::COEFFICIENT);

	ILVector2n ilv_dcrt2(ilParams2);
	bbv2.SetModulus(ilParams2.GetModulus());
	ilv_dcrt2.SetValues(bbv2, Format::COEFFICIENT);
	ilvectors_dcrt_vector_1.reserve(2);
	ilvectors_dcrt_vector_1.push_back(ilv_single_crt1_dcrt1);
	ilvectors_dcrt_vector_1.push_back(ilv_dcrt2);

	ilvectors_single_crt_vector.reserve(2);
	ilvectors_single_crt_vector.push_back(ilv_single_crt1_dcrt1);
	ilvectors_single_crt_vector.push_back(ilv_single_crt2);

	ILVector2n ilv_dcrt3(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv3(m / 2, ilParams1.GetModulus());
	bbv3.SetValAtIndex(0, "1");
	bbv3.SetValAtIndex(1, "0");
	bbv3.SetValAtIndex(2, "9");
	bbv3.SetValAtIndex(3, "0");
	bbv3.SetValAtIndex(4, "12304");
	bbv3.SetValAtIndex(5, "100");
	bbv3.SetValAtIndex(6, "0");
	bbv3.SetValAtIndex(7, "1");
	ilv_dcrt3.SetValues(bbv3, Format::COEFFICIENT);

	ILVector2n ilv_dcrt4(ilParams2);
	BigBinaryVector bbv4(m / 2, ilParams2.GetModulus());
	bbv4.SetValAtIndex(0, "0");
	bbv4.SetValAtIndex(1, "1");
	bbv4.SetValAtIndex(2, "2");
	bbv4.SetValAtIndex(3, "0");
	bbv4.SetValAtIndex(4, "1");
	bbv4.SetValAtIndex(5, "17729");
	bbv4.SetValAtIndex(6, "3");
	bbv4.SetValAtIndex(7, "0");
	ilv_dcrt4.SetValues(bbv4, Format::COEFFICIENT);

	ilvectors_dcrt_vector_2.reserve(2);
	ilvectors_dcrt_vector_2.push_back(ilv_dcrt3);
	ilvectors_dcrt_vector_2.push_back(ilv_dcrt4);

	//Intializing Ciphertext for ILVector2n
	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(4);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(ilParams1);

	cipher1_single_crt.SetCryptoParameters(&cryptoParams);
	cipher1_single_crt.SetElement(ilv_single_crt1_dcrt1);

	cipher2_single_crt = cipher1_single_crt;
	cipher2_single_crt.SetElement(ilv_single_crt2);

	//Initalizing Ciphertext for ILVectorArray2n
	ILVectorArray2n ilv_dcrt_1(ilvectors_dcrt_vector_1);
	ILVectorArray2n ilv_dcrt_2(ilvectors_dcrt_vector_2);

	vector<BigBinaryInteger> moduli;
	moduli.reserve(2);
	moduli.push_back(ilParams1.GetModulus());
	moduli.push_back(ilParams2.GetModulus());

	vector<BigBinaryInteger> rootsOfUnity;
	rootsOfUnity.reserve(2);
	rootsOfUnity.push_back(ilParams1.GetRootOfUnity());
	rootsOfUnity.push_back(ilParams2.GetRootOfUnity());

	ILDCRTParams ildcrtparams(ilParams1.GetCyclotomicOrder(), moduli, rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams_dcrt;
	cryptoParams_dcrt.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams_dcrt.SetDistributionParameter(4);
	cryptoParams_dcrt.SetRelinWindow(1);
	cryptoParams_dcrt.SetElementParams(ildcrtparams);

	cipher1_dcrt.SetCryptoParameters(&cryptoParams_dcrt);

	cipher1_dcrt.SetElement(ilv_dcrt_1);

	cipher2_dcrt.SetCryptoParameters(&cryptoParams_dcrt);
	cipher2_dcrt.SetElement(ilv_dcrt_2);

	//Testing eval_add in coefficient format for ILVector2n
	Ciphertext<ILVector2n> resultsILVector2n(cipher1_single_crt);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(SHE);
	algorithm.EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);

	ILVector2n resultsIlv(cipher1_single_crt.GetElement());
	BigBinaryVector bbvResults(m / 2, cipher1_single_crt.GetElement().GetModulus());
	bbvResults.SetValAtIndex(0, "5");
	bbvResults.SetValAtIndex(1, "3597");
	bbvResults.SetValAtIndex(2, "4");
	bbvResults.SetValAtIndex(3, "0");
	bbvResults.SetValAtIndex(4, "12302");
	bbvResults.SetValAtIndex(5, "33");
	bbvResults.SetValAtIndex(6, "1");
	bbvResults.SetValAtIndex(7, "6");
	resultsIlv.SetValues(bbvResults, Format::COEFFICIENT);

	EXPECT_EQ(resultsILVector2n.GetElement(), resultsIlv);
	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(), Format::COEFFICIENT);

	//Testing eval_add in Evaluation format for ILVector2n
	ilvectors_single_crt_vector[0].SwitchFormat();
	cipher1_single_crt.SetElement(ilvectors_single_crt_vector[0]);
	ilvectors_single_crt_vector[1].SwitchFormat();
	cipher2_single_crt.SetElement(ilvectors_single_crt_vector[1]);
	resultsIlv.SwitchFormat();

	algorithm.EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);
	EXPECT_EQ(resultsILVector2n.GetElement(), resultsIlv);
	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(), Format::EVALUATION);

	//Creating ILVectorArray2n Ciphertext with expected results for EvalAdd
	ILVector2n ilv_dcrt_results_1(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv_dcrt_results_1(m / 2, ilParams1.GetModulus());
	bbv_dcrt_results_1.SetValAtIndex(0, "5");
	bbv_dcrt_results_1.SetValAtIndex(1, "3594");
	bbv_dcrt_results_1.SetValAtIndex(2, "11");
	bbv_dcrt_results_1.SetValAtIndex(3, "0");
	bbv_dcrt_results_1.SetValAtIndex(4, "6876");
	bbv_dcrt_results_1.SetValAtIndex(5, "101");
	bbv_dcrt_results_1.SetValAtIndex(6, "0");
	bbv_dcrt_results_1.SetValAtIndex(7, "7");
	ilv_dcrt_results_1.SetValues(bbv_dcrt_results_1, Format::COEFFICIENT);

	ILVector2n ilv_dcrt_results_2(ilParams2);
	BigBinaryVector bbv_dcrt_results_2(m / 2, ilParams2.GetModulus());
	bbv_dcrt_results_2.SetValAtIndex(0, "1");
	bbv_dcrt_results_2.SetValAtIndex(1, "4");
	bbv_dcrt_results_2.SetValAtIndex(2, "4");
	bbv_dcrt_results_2.SetValAtIndex(3, "0");
	bbv_dcrt_results_2.SetValAtIndex(4, "17731");
	bbv_dcrt_results_2.SetValAtIndex(5, "0");
	bbv_dcrt_results_2.SetValAtIndex(6, "4");
	bbv_dcrt_results_2.SetValAtIndex(7, "0");
	ilv_dcrt_results_2.SetValues(bbv_dcrt_results_2, Format::COEFFICIENT);

	vector<ILVector2n> ilv_dcrt_results_vector;
	ilv_dcrt_results_vector.reserve(2);
	ilv_dcrt_results_vector.push_back(ilv_dcrt_results_1);
	ilv_dcrt_results_vector.push_back(ilv_dcrt_results_2);

	ILVectorArray2n ilv_dcrt_expectedResults(ilv_dcrt_results_vector);
	Ciphertext<ILVectorArray2n> cipher_dcrt_results(cipher1_dcrt);

	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm_dcrt;
	algorithm_dcrt.Enable(SHE);
	algorithm_dcrt.EvalAdd(cipher1_dcrt, cipher2_dcrt, &cipher_dcrt_results);

	EXPECT_EQ(cipher_dcrt_results.GetElement(), ilv_dcrt_expectedResults);

	//This should throw an error for the parameters not being the same for one the multiplied parties
	LPCryptoParametersLTV<ILVector2n> badCryptoParams(cryptoParams);
	badCryptoParams.SetElementParams(ilParams2);
	cipher1_single_crt.SetCryptoParameters(&badCryptoParams);
	EXPECT_ANY_THROW(algorithm.EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n));

	//This test case should fail because the ciphertext results has different parameters
	cipher1_single_crt.SetCryptoParameters(&cryptoParams);
	resultsILVector2n.SetCryptoParameters(&badCryptoParams);
	EXPECT_ANY_THROW(algorithm.EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n));

	
}

TEST_F(UnitTestSHEAdvanced, test_eval_mult) {
	//parameter setup
	usint m = 16;
	Ciphertext<ILVector2n> cipher1_single_crt;
	Ciphertext<ILVector2n> cipher2_single_crt;

	Ciphertext<ILVectorArray2n> cipher1_dcrt;
	Ciphertext<ILVectorArray2n> cipher2_dcrt;

	vector<ILVector2n> ilvectors_dcrt_vector_1;
	vector<ILVector2n> ilvectors_dcrt_vector_2;
	vector<ILVector2n> ilvectors_single_crt_vector;

	//q1 and q2 are precalculated prime modulis

	BigBinaryInteger q1("17729");
	BigBinaryInteger rootOfUnity1(RootOfUnity(m, q1));

	BigBinaryInteger q2("17761");
	BigBinaryInteger rootOfUnity2(RootOfUnity(m, q2));

	//setting up two parameters. ilparams2 will be only used for double-crt
	ILParams ilParams1(m, q1, rootOfUnity1);
	ILParams ilParams2(m, q2, rootOfUnity2);

	//construcing an ILVector2n, this 
	ILVector2n ilv_single_crt1_dcrt1(ilParams1); // Used for both single and double crt
	BigBinaryInteger modulus(ilParams1.GetModulus());
	BigBinaryVector bbv1(m / 2, modulus);
	bbv1.SetValAtIndex(0, "4");
	bbv1.SetValAtIndex(1, "21323");
	bbv1.SetValAtIndex(2, "2");
	bbv1.SetValAtIndex(3, "0");
	bbv1.SetValAtIndex(4, "12301");
	bbv1.SetValAtIndex(5, "1");
	bbv1.SetValAtIndex(6, "0");
	bbv1.SetValAtIndex(7, "6");
	ilv_single_crt1_dcrt1.SetValues(bbv1, Format::EVALUATION);

	ILVector2n ilv_single_crt2(ilParams1);
	BigBinaryVector bbv2(m / 2, ilParams1.GetModulus());
	bbv2.SetValAtIndex(0, "1");
	bbv2.SetValAtIndex(1, "3");
	bbv2.SetValAtIndex(2, "2");
	bbv2.SetValAtIndex(3, "0");
	bbv2.SetValAtIndex(4, "17730");
	bbv2.SetValAtIndex(5, "32");
	bbv2.SetValAtIndex(6, "1");
	bbv2.SetValAtIndex(7, "0");
	ilv_single_crt2.SetValues(bbv2, Format::EVALUATION);

	ILVector2n ilv_dcrt2(ilParams2);
	bbv2.SetModulus(ilParams2.GetModulus());
	ilv_dcrt2.SetValues(bbv2, Format::EVALUATION);
	ilvectors_dcrt_vector_1.reserve(2);
	ilvectors_dcrt_vector_1.push_back(ilv_single_crt1_dcrt1);
	ilvectors_dcrt_vector_1.push_back(ilv_dcrt2);

	ilvectors_single_crt_vector.reserve(2);
	ilvectors_single_crt_vector.push_back(ilv_single_crt1_dcrt1);
	ilvectors_single_crt_vector.push_back(ilv_single_crt2);

	ILVector2n ilv_dcrt3(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv3(m / 2, ilParams1.GetModulus());
	bbv3.SetValAtIndex(0, "1");
	bbv3.SetValAtIndex(1, "0");
	bbv3.SetValAtIndex(2, "9");
	bbv3.SetValAtIndex(3, "0");
	bbv3.SetValAtIndex(4, "12304");
	bbv3.SetValAtIndex(5, "100");
	bbv3.SetValAtIndex(6, "0");
	bbv3.SetValAtIndex(7, "1");
	ilv_dcrt3.SetValues(bbv3, Format::EVALUATION);

	ILVector2n ilv_dcrt4(ilParams2);
	BigBinaryVector bbv4(m / 2, ilParams2.GetModulus());
	bbv4.SetValAtIndex(0, "0");
	bbv4.SetValAtIndex(1, "1");
	bbv4.SetValAtIndex(2, "2");
	bbv4.SetValAtIndex(3, "0");
	bbv4.SetValAtIndex(4, "1");
	bbv4.SetValAtIndex(5, "17729");
	bbv4.SetValAtIndex(6, "3");
	bbv4.SetValAtIndex(7, "0");
	ilv_dcrt4.SetValues(bbv4, Format::EVALUATION);

	ilvectors_dcrt_vector_2.reserve(2);
	ilvectors_dcrt_vector_2.push_back(ilv_dcrt3);
	ilvectors_dcrt_vector_2.push_back(ilv_dcrt4);

	//Intializing Ciphertext for ILVector2n
	LPCryptoParametersLTV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(4);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(ilParams1);

	cipher1_single_crt.SetCryptoParameters(&cryptoParams);
	cipher1_single_crt.SetElement(ilv_single_crt1_dcrt1);

	cipher2_single_crt = cipher1_single_crt;
	cipher2_single_crt.SetElement(ilv_single_crt2);

	//Initalizing Ciphertext for ILVectorArray2n
	ILVectorArray2n ilv_dcrt_1(ilvectors_dcrt_vector_1);
	ILVectorArray2n ilv_dcrt_2(ilvectors_dcrt_vector_2);

	vector<BigBinaryInteger> moduli;
	moduli.reserve(2);
	moduli.push_back(ilParams1.GetModulus());
	moduli.push_back(ilParams2.GetModulus());

	vector<BigBinaryInteger> rootsOfUnity;
	rootsOfUnity.reserve(2);
	rootsOfUnity.push_back(ilParams1.GetRootOfUnity());
	rootsOfUnity.push_back(ilParams2.GetRootOfUnity());

	ILDCRTParams ildcrtparams(ilParams1.GetCyclotomicOrder(), moduli, rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams_dcrt;
	cryptoParams_dcrt.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams_dcrt.SetDistributionParameter(4);
	cryptoParams_dcrt.SetRelinWindow(1);
	cryptoParams_dcrt.SetElementParams(ildcrtparams);

	cipher1_dcrt.SetCryptoParameters(&cryptoParams_dcrt);

	cipher1_dcrt.SetElement(ilv_dcrt_1);

	cipher2_dcrt.SetCryptoParameters(&cryptoParams_dcrt);
	cipher2_dcrt.SetElement(ilv_dcrt_2);

	//Testing eval_add in coefficient format for ILVector2n
	Ciphertext<ILVector2n> resultsILVector2n(cipher1_single_crt);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(SHE);
	algorithm.EvalMult(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);

	ILVector2n resultsIlv(cipher1_single_crt.GetElement());
	BigBinaryVector bbvResults(m / 2, cipher1_single_crt.GetElement().GetModulus());
	bbvResults.SetValAtIndex(0, "4");
	bbvResults.SetValAtIndex(1, "10782");
	bbvResults.SetValAtIndex(2, "4");
	bbvResults.SetValAtIndex(3, "0");
	bbvResults.SetValAtIndex(4, "12301");
	bbvResults.SetValAtIndex(5, "32");
	bbvResults.SetValAtIndex(6, "0");
	bbvResults.SetValAtIndex(7, "0");
	resultsIlv.SetValues(bbvResults, Format::EVALUATION);

	EXPECT_EQ(resultsILVector2n.GetElement(), resultsIlv);
	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(), Format::EVALUATION);

	//Creating ILVectorArray2n Ciphertext with expected results for EvalAdd
	ILVector2n ilv_dcrt_results_1(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv_dcrt_results_1(m / 2, ilParams1.GetModulus());
	bbv_dcrt_results_1.SetValAtIndex(0, "4");
	bbv_dcrt_results_1.SetValAtIndex(1, "0");
	bbv_dcrt_results_1.SetValAtIndex(2, "18");
	bbv_dcrt_results_1.SetValAtIndex(3, "0");
	bbv_dcrt_results_1.SetValAtIndex(4, "16760");
	bbv_dcrt_results_1.SetValAtIndex(5, "100");
	bbv_dcrt_results_1.SetValAtIndex(6, "0");
	bbv_dcrt_results_1.SetValAtIndex(7, "6");
	ilv_dcrt_results_1.SetValues(bbv_dcrt_results_1, Format::EVALUATION);

	ILVector2n ilv_dcrt_results_2(ilParams2);
	BigBinaryVector bbv_dcrt_results_2(m / 2, ilParams2.GetModulus());
	bbv_dcrt_results_2.SetValAtIndex(0, "0");
	bbv_dcrt_results_2.SetValAtIndex(1, "3");
	bbv_dcrt_results_2.SetValAtIndex(2, "4");
	bbv_dcrt_results_2.SetValAtIndex(3, "0");
	bbv_dcrt_results_2.SetValAtIndex(4, "17730");
	bbv_dcrt_results_2.SetValAtIndex(5, "16737");
	bbv_dcrt_results_2.SetValAtIndex(6, "3");
	bbv_dcrt_results_2.SetValAtIndex(7, "0");
	ilv_dcrt_results_2.SetValues(bbv_dcrt_results_2, Format::EVALUATION);

	vector<ILVector2n> ilv_dcrt_results_vector;
	ilv_dcrt_results_vector.reserve(2);
	ilv_dcrt_results_vector.push_back(ilv_dcrt_results_1);
	ilv_dcrt_results_vector.push_back(ilv_dcrt_results_2);

	ILVectorArray2n ilv_dcrt_expectedResults(ilv_dcrt_results_vector);
	Ciphertext<ILVectorArray2n> cipher_dcrt_results(cipher1_dcrt);

	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm_dcrt;
	algorithm_dcrt.Enable(SHE);
	algorithm_dcrt.EvalMult(cipher1_dcrt, cipher2_dcrt, &cipher_dcrt_results);

	EXPECT_EQ(cipher_dcrt_results.GetElement(), ilv_dcrt_expectedResults);

	//NEGATIVE TEST CASES

	//This should throw an error for the parameters not being the same for one the multiplied parties
	LPCryptoParametersLTV<ILVector2n> badCryptoParams(cryptoParams);
	badCryptoParams.SetElementParams(ilParams2);
	cipher1_single_crt.SetCryptoParameters(&badCryptoParams);
	EXPECT_ANY_THROW(algorithm.EvalMult(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n));

	//This test case should fail because the ciphertext results has different parameters
	cipher1_single_crt.SetCryptoParameters(&cryptoParams);
	resultsILVector2n.SetCryptoParameters(&badCryptoParams);
	EXPECT_ANY_THROW(algorithm.EvalMult(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n));

	//This should throw an error since the format is not in Coefficient
	resultsILVector2n.SetCryptoParameters(&cryptoParams);
	ilv_single_crt1_dcrt1.SwitchFormat();
	ilv_dcrt3.SwitchFormat();
	cipher1_single_crt.SetElement(ilv_single_crt1_dcrt1);
	cipher2_single_crt.SetElement(ilv_dcrt3);
	EXPECT_ANY_THROW(algorithm.EvalMult(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n));
}




/*Testing Parameter selection. The test will check if generated parameters are greater than the following thresholds:
* The first modulus generated needs to be greater than q1 > 4pr sqrt(n) w. Where
* p is the plaintext modulus
* r is Gaussian Parameter
* w is the assurance measure
* n is the ring dimension
*/

TEST_F(UnitTestSHEAdvanced, ParameterSelection) {


	usint m = 16; // initial cycltomic order

	float stdDev = 4;

	usint size = 11; // tower size, equal to depth of operation + 1

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

	//intializing cryptoparameters alongside variables
	DiscreteGaussianGenerator dgg(stdDev);
	ILDCRTParams params(m, moduli, rootsOfUnity);
	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	cryptoParams.SetDistributionParameter(stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	//New CryptoParameters placeholder
	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams2;
	//calling ParameterSelection. cryptoParams2 will have the new Moduli and ring dimension (cyclotomicorder/2)
	cryptoParams.ParameterSelection(&cryptoParams2);

	const ILDCRTParams &dcrtParams = static_cast<const ILDCRTParams&>(cryptoParams2.GetElementParams());
	std::vector<BigBinaryInteger> finalModuli = dcrtParams.GetModuli();
	//threshold for the first modulus
	double q1Threshold = 4 * pow(cryptoParams2.GetPlaintextModulus().ConvertToDouble(), 2) * pow(cryptoParams2.GetElementParams().GetCyclotomicOrder() / 2, 0.5) * cryptoParams2.GetAssuranceMeasure();
	//test for the first modulus
	EXPECT_LT(q1Threshold, finalModuli[0].ConvertToDouble());
	//threshold for all but the first modulus
	double q2Threshold = 4 * pow(cryptoParams2.GetPlaintextModulus().ConvertToDouble(), 2) * pow(cryptoParams2.GetDistributionParameter(), 5) * pow(cryptoParams2.GetElementParams().GetCyclotomicOrder() / 2, 1.5) * pow(cryptoParams2.GetAssuranceMeasure(), 5);

	//test for all but the first modulus
	for (usint i = 1; i < finalModuli.size(); i++) {
		EXPECT_LT(q2Threshold, finalModuli[i].ConvertToDouble());
	}
}

TEST_F(UnitTestSHEAdvanced, test_composed_eval_mult_two_towers) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	vector<BigBinaryInteger> init_moduli(init_size);

	vector<BigBinaryInteger> init_rootsOfUnity(init_size);

	BigBinaryInteger q("1");
	BigBinaryInteger temp;
	BigBinaryInteger modulus("1");

	for (int i = 0; i < init_size; i++) {
		lbcrypto::NextQ(q, BigBinaryInteger::FIVE, init_m, BigBinaryInteger("4"), BigBinaryInteger("4"));
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus* init_moduli[i];

	}

	DiscreteGaussianGenerator dgg(init_stdDev);

	ILDCRTParams params(init_m, init_moduli, init_rootsOfUnity);

	LPCryptoParametersLTV<ILVectorArray2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::FIVE + BigBinaryInteger::FOUR);
	cryptoParams.SetDistributionParameter(init_stdDev);
	cryptoParams.SetRelinWindow(1);
	cryptoParams.SetElementParams(params);
	cryptoParams.SetDiscreteGaussianGenerator(dgg);
	cryptoParams.SetAssuranceMeasure(6);
	cryptoParams.SetDepth(init_size - 1);
	cryptoParams.SetSecurityLevel(1.006);

	usint n = 16;

	LPCryptoParametersLTV<ILVectorArray2n> finalParamsTwoTowers;

	cryptoParams.ParameterSelection(&finalParamsTwoTowers);

	const ILDCRTParams &dcrtParams = dynamic_cast<const ILDCRTParams&>(finalParamsTwoTowers.GetElementParams());

	usint m = dcrtParams.GetCyclotomicOrder();
	usint size = finalParamsTwoTowers.GetDepth() + 1;
	const BigBinaryInteger &plainTextModulus = finalParamsTwoTowers.GetPlaintextModulus();
	//scheme initialization: LTV Scheme
	LPPublicKeyEncryptionSchemeLTV<ILVectorArray2n> algorithm;
	algorithm.Enable(SHE);
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(LEVELEDSHE);

	//Generate the secret key for the initial ciphertext:
	LPPublicKey<ILVectorArray2n> pk(finalParamsTwoTowers);
	LPPrivateKey<ILVectorArray2n> sk(finalParamsTwoTowers);
	algorithm.KeyGen(&pk, &sk);

	//Generate the keys for level 1, same number of towers
	LPPublicKey<ILVectorArray2n> pk1(finalParamsTwoTowers);
	LPPrivateKey<ILVectorArray2n> sk1(finalParamsTwoTowers);
	algorithm.KeyGen(&pk1, &sk1);

	//Generating new cryptoparameters for when modulus reduction is done.
	LPCryptoParametersLTV<ILVectorArray2n> finalParamsOneTower(finalParamsTwoTowers);

	const ILDCRTParams &dcrtParamsWithOneTowers = dynamic_cast<const ILDCRTParams&>(finalParamsTwoTowers.GetElementParams());
	ILDCRTParams dcrtParamsWith1Tower(dcrtParamsWithOneTowers);
	dcrtParamsWith1Tower.PopLastParam();
	finalParamsOneTower.SetElementParams(dcrtParamsWith1Tower);

	//Generating Quaraditic KeySwitchHint from sk^2 to skNew
	LPEvalKeyNTRU<ILVectorArray2n> quadraticKeySwitchHint;
	algorithm.QuadraticKeySwitchHintGen(sk, sk1, &quadraticKeySwitchHint);

	//Dropping the last tower of skNew, because ComposedEvalMult performs a ModReduce
	sk1.SetCryptoParameters(&finalParamsOneTower);
	ILVectorArray2n skNewOldElement(sk1.GetPrivateElement());
	skNewOldElement.DropElementAtIndex(skNewOldElement.GetNumOfElements() - 1);
	sk1.SetPrivateElement(skNewOldElement);

	std::vector<usint> firstElement(2048);
	firstElement.at(0) = 8;

	std::fill(firstElement.begin() + 1, firstElement.end(), 0);

	IntPlaintextEncoding firstElementEncoding(firstElement);

	std::vector<usint> secondElement(2048);
	secondElement.at(0) = 7;
	
	std::fill(secondElement.begin() + 1, secondElement.end(), 0);
	IntPlaintextEncoding secondElementEncoding(secondElement);

	//Generating original ciphertext to perform ComposedEvalMult on
	Ciphertext<ILVectorArray2n> c1;
	c1.SetCryptoParameters(&finalParamsTwoTowers);

	Ciphertext<ILVectorArray2n> c2;
	c2.SetCryptoParameters(&finalParamsTwoTowers);

	Ciphertext<ILVectorArray2n> cResult;
	cResult.SetCryptoParameters(&finalParamsTwoTowers);

	/*algorithm.Encrypt(pk, firstElement, &c1);
	algorithm.Encrypt(pk, secondElement, &c2);*/
	vector<Ciphertext<ILVectorArray2n>> ciphertextElementOne;
	vector<Ciphertext<ILVectorArray2n>> ciphertextElementTwo;

	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, firstElementEncoding, &ciphertextElementOne, false);
	CryptoUtility<ILVectorArray2n>::Encrypt(algorithm, pk, secondElementEncoding, &ciphertextElementTwo, false);

	algorithm.ComposedEvalMult(ciphertextElementOne.at(0), ciphertextElementTwo.at(0), quadraticKeySwitchHint, &cResult);

	IntPlaintextEncoding results;

	vector<Ciphertext<ILVectorArray2n>> ciphertextResults(1);
	ciphertextResults.at(0) = cResult;
	
	CryptoUtility<ILVectorArray2n>::Decrypt(algorithm, sk1, ciphertextResults, &results, false);

	EXPECT_EQ(results.at(0), 2);

}
