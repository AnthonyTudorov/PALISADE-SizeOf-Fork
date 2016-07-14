#include "../include/gtest/gtest.h"
#include <iostream>

#include "../../src/lib/math/backend.h"
#include "../../src/lib/utils/inttypes.h"
#include "../../src/lib/math/nbtheory.h"
#include "../../src/lib/lattice/elemparams.h"
#include "../../src/lib/lattice/ilparams.h"
#include "../../src/lib/lattice/ildcrtparams.h"
#include "../../src/lib/lattice/ilelement.h"
#include "../../src/lib/math/distrgen.h"
#include "../../src/lib/crypto/lwecrypt.h"
#include "../../src/lib/crypto/lwepre.h"
#include "../../src/lib/lattice/ilvector2n.h"
#include "../../src/lib/lattice/ilvectorarray2n.h"
#include "../../src/lib/utils/utilities.h"

#include "../../src/lib/crypto/lwecrypt.cpp"
#include "../../src/lib/crypto/ciphertext.cpp"
 
using namespace std;
 
// A new one of these is created for each test
class UnitTestSHE2 : public testing::Test
{
public:
	UnitTestSHE2(){}
	/*Ciphertext<ILVector2n> cipher1_single_crt;
	Ciphertext<ILVector2n> cipher2_single_crt;

	Ciphertext<ILVectorArray2n> cipher1_dcrt;
	Ciphertext<ILVectorArray2n> cipher2_ccrt;

	vector<ILVector2n> ilvectors_dcrt_vector_1;
	vector<ILVector2n> ilvectors_dcrt_vector_2;
	vector<ILVector2n> ilvectors_single_crt_vector;*/

	//LPCryptoParametersLTV<ILVector2n> *cryptoParams;
	//LPCryptoParametersLTV<ILVectorArray2n> *cryptoParams_dcrt;

  virtual void SetUp()
  {

	//BigBinaryInteger q1("17729");
 //   BigBinaryInteger rootOfUnity1(RootOfUnity(m,q1));
 //   ILParams ilParams1(m,q1,rootOfUnity1);
 // 
	//BigBinaryInteger q2("17761");
 //   BigBinaryInteger rootOfUnity2(RootOfUnity(m,q2));
 //   ILParams ilParams2(m,q2,rootOfUnity2);

	//ILVector2n ilv_single_crt1(ilParams1); // Used for both single and double crt
	//BigBinaryVector bbv1(m/2, ilParams1.GetModulus());
 //   bbv1.SetValAtIndex(0, "4");
 //   bbv1.SetValAtIndex(1, "21323");
 //   bbv1.SetValAtIndex(2, "2");
 //   bbv1.SetValAtIndex(3, "0");
	//bbv1.SetValAtIndex(4, "12301");
 //   bbv1.SetValAtIndex(5, "1");
	//bbv1.SetValAtIndex(6, "0");
	//bbv1.SetValAtIndex(7, "6");
	//ilv_single_crt1.SetValues(bbv1, Format::COEFFICIENT);

	//ILVector2n ilv_single_crt2(ilParams1);
	//BigBinaryVector bbv2(m/2, ilParams1.GetModulus());
 //   bbv2.SetValAtIndex(0, "1");
 //   bbv2.SetValAtIndex(1, "3");
 //   bbv2.SetValAtIndex(2, "2");
 //   bbv2.SetValAtIndex(3, "0");
	//bbv2.SetValAtIndex(4, "17730");
 //   bbv2.SetValAtIndex(5, "32");
	//bbv2.SetValAtIndex(6, "1");
	//bbv2.SetValAtIndex(7, "0");
	//ilv_single_crt2.SetValues(bbv2, Format::COEFFICIENT);

	//ilvectors_single_crt_vector.reserve(2);
	//ilvectors_single_crt_vector.push_back(ilv_single_crt1);
	//ilvectors_single_crt_vector.push_back(ilv_single_crt2);

	//ILVector2n ilv_dcrt2(ilParams2);
	//bbv2.SetModulus(ilParams2.GetModulus());
	//ilv_dcrt2.SetValues(bbv2, Format::COEFFICIENT);
	//ilvectors_dcrt_vector_1.reserve(2);
	//ilvectors_dcrt_vector_1.push_back(ilv_single_crt1);
	//ilvectors_dcrt_vector_2.push_back(ilv_dcrt2);

	//ILVector2n ilv_dcrt3(ilParams1); // Used for both single and double crt
	//BigBinaryVector bbv3(m/2, ilParams1.GetModulus());
 //   bbv3.SetValAtIndex(0, "1");
 //   bbv3.SetValAtIndex(1, "0");
 //   bbv3.SetValAtIndex(2, "9");
 //   bbv3.SetValAtIndex(3, "0");
	//bbv3.SetValAtIndex(4, "12304");
 //   bbv3.SetValAtIndex(5, "100");
	//bbv3.SetValAtIndex(6, "0");
	//bbv3.SetValAtIndex(7, "1");
	//ilv_dcrt3.SetValues(bbv3, Format::COEFFICIENT);

	//ILVector2n ilv_dcrt4(ilParams2);
	//BigBinaryVector bbv4(m/2, ilParams2.GetModulus());
 //   bbv4.SetValAtIndex(0, "0");
 //   bbv4.SetValAtIndex(1, "1");
 //   bbv4.SetValAtIndex(2, "2");
 //   bbv4.SetValAtIndex(3, "0");
	//bbv4.SetValAtIndex(4, "1");
 //   bbv4.SetValAtIndex(5, "17729");
	//bbv4.SetValAtIndex(6, "3");
	//bbv4.SetValAtIndex(7, "0");
	//ilv_dcrt4.SetValues(bbv4, Format::COEFFICIENT);

	//ilvectors_dcrt_vector_2.reserve(2);
	//ilvectors_dcrt_vector_2.push_back(ilv_dcrt3);
	//ilvectors_dcrt_vector_2.push_back(ilv_dcrt4);


	////Intializing Ciphertext for ILVector2n
	//LPCryptoParametersLTV<ILVector2n> cryptoParams;
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);
	//cryptoParams.SetDistributionParameter(4);
	//cryptoParams.SetRelinWindow(1);
	//cryptoParams.SetElementParams(ilParams1);

	//cipher1_single_crt.SetCryptoParameters(&cryptoParams);
	//cipher1_single_crt.SetElement(ilv_single_crt1);
	//
	//cipher2_single_crt = cipher1_single_crt;
	//cipher2_single_crt.SetElement(ilv_single_crt2);

	////Initalizing Ciphertext for ILVectorArray2n
	//ILVectorArray2n ilv_dcrt_1(ilvectors_dcrt_vector_1);
	//ILVectorArray2n ilv_dcrt_2(ilvectors_dcrt_vector_2);

	//vector<BigBinaryInteger> moduli;
	//moduli.reserve(2);
	//moduli.push_back(ilParams1.GetModulus());
	//moduli.push_back(ilParams2.GetModulus());

	//vector<BigBinaryInteger> rootsOfUnity;
	//rootsOfUnity.reserve(2);
	//rootsOfUnity.push_back(ilParams1.GetRootOfUnity());
	//rootsOfUnity.push_back(ilParams2.GetRootOfUnity());

	//ILDCRTParams ildcrtparams(ilParams1.GetCyclotomicOrder(), moduli, rootsOfUnity);
	//
	//LPCryptoParametersLTV<ILVectorArray2n> cryptoParams_dcrt;
	//cryptoParams_dcrt.SetPlaintextModulus(BigBinaryInteger::TWO);
	//cryptoParams_dcrt.SetDistributionParameter(4);
	//cryptoParams_dcrt.SetRelinWindow(1);
	//cryptoParams_dcrt.SetElementParams(ildcrtparams);

	//cipher1_dcrt.SetCryptoParameters(&cryptoParams_dcrt);
	//
	//cipher1_dcrt.SetElement(ilvectors_dcrt_vector_1);

  }
 
  virtual void TearDown()
  {
  }
};
 
//TEST_F(UnitTestSHE2, test_eval_add)
//{

// 
//	//Testing eval_add in coefficient format for ILVector2n
//	Ciphertext<ILVector2n> resultsILVector2n(cipher1_single_crt);
//
//	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
//	algorithm.Enable(SHE);
//	algorithm.m_algorithmSHE->EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);
//
//	ILVector2n resultsIlv(cipher1_single_crt.GetElement());
//	BigBinaryVector bbvResults(m/2, cipher1_single_crt.GetElement().GetModulus());
//    bbvResults.SetValAtIndex(0, "5");
//    bbvResults.SetValAtIndex(1, "3597");
//    bbvResults.SetValAtIndex(2, "4");
//    bbvResults.SetValAtIndex(3, "0");
//	bbvResults.SetValAtIndex(4, "12302");
//    bbvResults.SetValAtIndex(5, "33");
//	bbvResults.SetValAtIndex(6, "1");
//	bbvResults.SetValAtIndex(7, "6");
//	resultsIlv.SetValues(bbvResults, Format::COEFFICIENT);
//
//	EXPECT_EQ(cryptoParams, cryptoParams);
//
////	EXPECT_EQ(resultsILVector2n.GetElement(),resultsIlv);
////	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(),Format::COEFFICIENT);
//
//	//Testing eval_add in Evaluation format for ILVector2n
//	ilvectors_single_crt_vector[0].SwitchFormat();
//	cipher1_single_crt.SetElement(ilvectors_single_crt_vector[0]);
//	ilvectors_single_crt_vector[1].SwitchFormat();
//	cipher2_single_crt.SetElement(ilvectors_single_crt_vector[1]);
//	resultsIlv.SwitchFormat();
//
//	algorithm.m_algorithmSHE->EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);
////	EXPECT_EQ(resultsILVector2n.GetElement(),resultsIlv);
////	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(),Format::EVALUATION);

//}

TEST(UnitTestSHE2, test_eval_add){

	usint m = 16;
	Ciphertext<ILVector2n> cipher1_single_crt;
	Ciphertext<ILVector2n> cipher2_single_crt;

	Ciphertext<ILVectorArray2n> cipher1_dcrt;
	Ciphertext<ILVectorArray2n> cipher2_dcrt;

	vector<ILVector2n> ilvectors_dcrt_vector_1;
	vector<ILVector2n> ilvectors_dcrt_vector_2;
	vector<ILVector2n> ilvectors_single_crt_vector;

	BigBinaryInteger q1("17729");
    BigBinaryInteger rootOfUnity1(RootOfUnity(m,q1));
    ILParams ilParams1(m,q1,rootOfUnity1);
  
	BigBinaryInteger q2("17761");
    BigBinaryInteger rootOfUnity2(RootOfUnity(m,q2));
    ILParams ilParams2(m,q2,rootOfUnity2);

	ILVector2n ilv_single_crt1(ilParams1); // Used for both single and double crt
	BigBinaryInteger modulus(ilParams1.GetModulus());
	BigBinaryVector bbv1(m/2, modulus);
    bbv1.SetValAtIndex(0, "4");
    bbv1.SetValAtIndex(1, "21323");
    bbv1.SetValAtIndex(2, "2");
    bbv1.SetValAtIndex(3, "0");
	bbv1.SetValAtIndex(4, "12301");
    bbv1.SetValAtIndex(5, "1");
	bbv1.SetValAtIndex(6, "0");
	bbv1.SetValAtIndex(7, "6");
	ilv_single_crt1.SetValues(bbv1, Format::COEFFICIENT);

	ILVector2n ilv_single_crt2(ilParams1);
	BigBinaryVector bbv2(m/2, ilParams1.GetModulus());
    bbv2.SetValAtIndex(0, "1");
    bbv2.SetValAtIndex(1, "3");
    bbv2.SetValAtIndex(2, "2");
    bbv2.SetValAtIndex(3, "0");
	bbv2.SetValAtIndex(4, "17730");
    bbv2.SetValAtIndex(5, "32");
	bbv2.SetValAtIndex(6, "1");
	bbv2.SetValAtIndex(7, "0");
	ilv_single_crt2.SetValues(bbv2, Format::COEFFICIENT);

	ilvectors_single_crt_vector.reserve(2);
	ilvectors_single_crt_vector.push_back(ilv_single_crt1);
	ilvectors_single_crt_vector.push_back(ilv_single_crt2);

	ILVector2n ilv_dcrt2(ilParams2);
	bbv2.SetModulus(ilParams2.GetModulus());
	ilv_dcrt2.SetValues(bbv2, Format::COEFFICIENT);
	ilvectors_dcrt_vector_1.reserve(2);
	ilvectors_dcrt_vector_1.push_back(ilv_single_crt1);
	ilvectors_dcrt_vector_2.push_back(ilv_dcrt2);

	ILVector2n ilv_dcrt3(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv3(m/2, ilParams1.GetModulus());
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
	BigBinaryVector bbv4(m/2, ilParams2.GetModulus());
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
	cipher1_single_crt.SetElement(ilv_single_crt1);
	
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
	algorithm.m_algorithmSHE->EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);

	ILVector2n resultsIlv(cipher1_single_crt.GetElement());
	BigBinaryVector bbvResults(m/2, cipher1_single_crt.GetElement().GetModulus());
    bbvResults.SetValAtIndex(0, "5");
    bbvResults.SetValAtIndex(1, "3597");
    bbvResults.SetValAtIndex(2, "4");
    bbvResults.SetValAtIndex(3, "0");
	bbvResults.SetValAtIndex(4, "12302");
    bbvResults.SetValAtIndex(5, "33");
	bbvResults.SetValAtIndex(6, "1");
	bbvResults.SetValAtIndex(7, "6");
	resultsIlv.SetValues(bbvResults, Format::COEFFICIENT);

	EXPECT_EQ(resultsILVector2n.GetElement(),resultsIlv);
	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(),Format::COEFFICIENT);

	//Testing eval_add in Evaluation format for ILVector2n
	ilvectors_single_crt_vector[0].SwitchFormat();
	cipher1_single_crt.SetElement(ilvectors_single_crt_vector[0]);
	ilvectors_single_crt_vector[1].SwitchFormat();
	cipher2_single_crt.SetElement(ilvectors_single_crt_vector[1]);
	resultsIlv.SwitchFormat();

	algorithm.m_algorithmSHE->EvalAdd(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);
	EXPECT_EQ(resultsILVector2n.GetElement(),resultsIlv);
	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(),Format::EVALUATION);

	//Creating ILVectorArray2n Ciphertext with expected results for EvalAdd
	ILVector2n ilv_dcrt_results_1(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv_dcrt_results_1(m/2, ilParams1.GetModulus());
    bbv_dcrt_results_1.SetValAtIndex(0, "1");
    bbv_dcrt_results_1.SetValAtIndex(1, "0");
    bbv_dcrt_results_1.SetValAtIndex(2, "9");
    bbv_dcrt_results_1.SetValAtIndex(3, "0");
	bbv_dcrt_results_1.SetValAtIndex(4, "12304");
    bbv_dcrt_results_1.SetValAtIndex(5, "100");
	bbv_dcrt_results_1.SetValAtIndex(6, "0");
	bbv_dcrt_results_1.SetValAtIndex(7, "1");
	ilv_dcrt_results_1.SetValues(bbv_dcrt_results_1, Format::EVALUATION);

	ILVector2n ilv_dcrt_results_2(ilParams2);
	BigBinaryVector bbv_dcrt_results_2(m/2, ilParams2.GetModulus());
    bbv_dcrt_results_2.SetValAtIndex(0, "0");
    bbv_dcrt_results_2.SetValAtIndex(1, "1");
    bbv_dcrt_results_2.SetValAtIndex(2, "2");
    bbv_dcrt_results_2.SetValAtIndex(3, "0");
	bbv_dcrt_results_2.SetValAtIndex(4, "1");
    bbv_dcrt_results_2.SetValAtIndex(5, "17729");
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
	algorithm_dcrt.m_algorithmSHE->EvalAdd(cipher1_dcrt, cipher2_dcrt, &cipher_dcrt_results);

//	EXPECT_EQ(cipher_dcrt_results.GetElement(), ilv_dcrt_expectedResults);
}

TEST(UnitTestSHE2, test_eval_mult){
	usint m = 16;

	Ciphertext<ILVector2n> cipher1_single_crt;
	Ciphertext<ILVector2n> cipher2_single_crt;

	Ciphertext<ILVectorArray2n> cipher1_dcrt;
	Ciphertext<ILVectorArray2n> cipher2_ccrt;

	vector<ILVector2n> ilvectors_dcrt_vector_1;
	vector<ILVector2n> ilvectors_dcrt_vector_2;
	vector<ILVector2n> ilvectors_single_crt_vector;

	BigBinaryInteger q1("17729");
    BigBinaryInteger rootOfUnity1(RootOfUnity(m,q1));
    ILParams ilParams1(m,q1,rootOfUnity1);
  
	BigBinaryInteger q2("17761");
    BigBinaryInteger rootOfUnity2(RootOfUnity(m,q2));
    ILParams ilParams2(m,q2,rootOfUnity2);

	ILVector2n ilv_single_crt1(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv1(m/2, ilParams1.GetModulus());
    bbv1.SetValAtIndex(0, "1324");
    bbv1.SetValAtIndex(1, "21323");
    bbv1.SetValAtIndex(2, "2");
    bbv1.SetValAtIndex(3, "0");
	bbv1.SetValAtIndex(4, "12301");
    bbv1.SetValAtIndex(5, "1");
	bbv1.SetValAtIndex(6, "0");
	bbv1.SetValAtIndex(7, "6123");
	ilv_single_crt1.SetValues(bbv1, Format::EVALUATION);

	ILVector2n ilv_single_crt2(ilParams1);
	BigBinaryVector bbv2(m/2, ilParams1.GetModulus());
    bbv2.SetValAtIndex(0, "1312");
    bbv2.SetValAtIndex(1, "3");
    bbv2.SetValAtIndex(2, "2");
    bbv2.SetValAtIndex(3, "0");
	bbv2.SetValAtIndex(4, "17730");
    bbv2.SetValAtIndex(5, "32");
	bbv2.SetValAtIndex(6, "1");
	bbv2.SetValAtIndex(7, "9123");
	ilv_single_crt2.SetValues(bbv2, Format::EVALUATION);

	ilvectors_single_crt_vector.reserve(2);
	ilvectors_single_crt_vector.push_back(ilv_single_crt1);
	ilvectors_single_crt_vector.push_back(ilv_single_crt2);

	ILVector2n ilv_dcrt2(ilParams2);
	bbv2.SetModulus(ilParams2.GetModulus());
	ilv_dcrt2.SetValues(bbv2, Format::EVALUATION);
	ilvectors_dcrt_vector_1.reserve(2);
	ilvectors_dcrt_vector_1.push_back(ilv_single_crt1);
	ilvectors_dcrt_vector_2.push_back(ilv_dcrt2);

	ILVector2n ilv_dcrt3(ilParams1); // Used for both single and double crt
	BigBinaryVector bbv3(m/2, ilParams1.GetModulus());
    bbv3.SetValAtIndex(0, "1");
    bbv3.SetValAtIndex(1, "0");
    bbv3.SetValAtIndex(2, "9");
    bbv3.SetValAtIndex(3, "0");
	bbv3.SetValAtIndex(4, "12304");
    bbv3.SetValAtIndex(5, "100");
	bbv3.SetValAtIndex(6, "0");
	bbv3.SetValAtIndex(7, "3645");
	ilv_dcrt3.SetValues(bbv3, Format::EVALUATION);

	ILVector2n ilv_dcrt4(ilParams2);
	BigBinaryVector bbv4(m/2, ilParams2.GetModulus());
    bbv4.SetValAtIndex(0, "123");
    bbv4.SetValAtIndex(1, "1");
    bbv4.SetValAtIndex(2, "2");
    bbv4.SetValAtIndex(3, "0");
	bbv4.SetValAtIndex(4, "1");
    bbv4.SetValAtIndex(5, "17729");
	bbv4.SetValAtIndex(6, "3");
	bbv4.SetValAtIndex(7, "1232");
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
	cipher1_single_crt.SetElement(ilv_single_crt1);
	
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
	
	cipher1_dcrt.SetElement(ilvectors_dcrt_vector_1);

		//Testing eval_add in coefficient format for ILVector2n
	Ciphertext<ILVector2n> resultsILVector2n(cipher1_single_crt);

	LPPublicKeyEncryptionSchemeLTV<ILVector2n> algorithm;
	algorithm.Enable(SHE);
	algorithm.m_algorithmSHE->EvalMult(cipher1_single_crt, cipher2_single_crt, &resultsILVector2n);

	ILVector2n resultsIlv(cipher1_single_crt.GetElement());
	BigBinaryVector bbvResults(m/2, cipher1_single_crt.GetElement().GetModulus());
    bbvResults.SetValAtIndex(0, "17375");
    bbvResults.SetValAtIndex(1, "10782");
    bbvResults.SetValAtIndex(2, "4");
    bbvResults.SetValAtIndex(3, "0");
	bbvResults.SetValAtIndex(4, "12301");
    bbvResults.SetValAtIndex(5, "32");
	bbvResults.SetValAtIndex(6, "0");
	bbvResults.SetValAtIndex(7, "13779");
	resultsIlv.SetValues(bbvResults, Format::EVALUATION);

	EXPECT_EQ(resultsILVector2n.GetElement(),resultsIlv);
	EXPECT_EQ(resultsILVector2n.GetElement().GetFormat(),Format::EVALUATION);

}