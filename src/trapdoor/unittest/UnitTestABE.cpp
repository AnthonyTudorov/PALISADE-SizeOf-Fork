/*
 * @file
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

//#include "../lib/cryptocontext.h"
#include "../lib/abe/cp_abe.h"
#include "../lib/abe/kp_abe.h"
#include "../lib/abe/kp_abe.cpp"
#include "../lib/abe/ibe.h"

//#include "lattice/elemparamfactory.h"

using namespace std;
using namespace lbcrypto;

template <class T>
class UTABE : public ::testing::Test {

public:


protected:
	UTABE() {}

	virtual void SetUp() {

	}

	virtual void TearDown() {

	}

	virtual ~UTABE() {  }

};

void UnitTestCPABE(int32_t base, usint k, usint ringDimension){

	usint n = ringDimension*2;
	usint ell = 4;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo);

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	RingMat pubElemBPos(zero_alloc, ell, m);
	RingMat pubElemBNeg(zero_alloc, ell, m);
	Poly u(pubElemBPos(0,0));

	CPABE pkg, sender, receiver;

	auto trapdoor = pkg.Setup(ilParams, base, ell, dug, &u, &pubElemBPos, &pubElemBNeg);

	EXPECT_NO_THROW(sender.Setup(ilParams, base, ell));
	EXPECT_NO_THROW(receiver.Setup(ilParams, base, ell));

	// User attributes (randomly generated binary values)

	usint *s = new usint[ell];
	// Access structure
	int *w = new int[ell];

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, m, ell+1);

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);
	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	Poly c1(dug, ilParams, EVALUATION);

	for(usint j=0; j<ell; j++)
		s[j] = rand()%2;

	for(usint j=0; j<ell; j++)
		w[j] = s[j];

	for(usint j=0; j<ell; j++)
		if(w[j]==1) {
			w[j] = 0;
			break;
		}

	for(usint j=0; j<ell; j++)
		if(s[j]==0) {
			w[j] = -1;
			break;
		}

	usint lenW = 0;
	for(usint j=0; j<ell; j++)
		if(w[j] != 0)
			lenW++;

	pkg.KeyGen(ilParams, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, trapdoor.second, dgg, &sk);

	Poly t1(ilParams, EVALUATION, true);
	Poly t2(ilParams, EVALUATION, true);

	for(usint i=0; i<ell; i++) {
			if(s[i]==1) {
				t2 = pubElemBPos(i, 0)*sk(0, i+1);
				for(usint j=1; j<m; j++)
					t2 += pubElemBPos(i, j)*sk(j, i+1);
			}
			else {
				t2 = pubElemBNeg(i, 0)*sk(0, i+1);
				for(usint j=1; j<m; j++)
					t2 += pubElemBNeg(i, j)*sk(j, i+1);
			}
			t1 += t2;
		}

		t2 = trapdoor.first(0, 0)*sk(0, 0);
		for(usint j=1; j<m; j++)
			t2 += trapdoor.first(0, j)*sk(j, 0);

		t1 += t2;

	EXPECT_EQ(t1,u);  //test key generation


	RingMat ctW(Poly::MakeAllocator(ilParams, EVALUATION), lenW+1, m);
	RingMat ctCPos(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);
	RingMat nC(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);

	// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
	ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
	ptext.SwitchFormat();

	EXPECT_NO_THROW(sender.Encrypt(ilParams, trapdoor.first, pubElemBPos, pubElemBNeg, u, w, ptext, dgg, dug, &ctW, &ctCPos, &nC, &c1));


	EXPECT_NO_THROW(receiver.Decrypt(w, s, sk, ctW, ctCPos, nC, c1, &dtext));

	ptext.SwitchFormat();

	EXPECT_EQ(ptext,dtext);

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();
	delete[] s;
	delete[] w;
}

void UnitTestKPABEBenchMarkCircuit(int32_t base, usint k, usint ringDimension){
	usint n = ringDimension*2;   // cyclotomic order
	usint ell = 2; // No of attributes

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> trapdoorA = RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base, true); // A.first is the public element

	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE<Poly, Poly> pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	usint x[] = {1,1,1}; // array of attributes, everything is set to 1 for NAND gate evaluation, values set based on experimental results

	usint y;

	// plaintext
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat evalBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  //evaluated Bs
	RingMat evalCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  // evaluated Cs
	RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m); // CA

	// secret key corresponding to the circuit output
	RingMat sk(zero_alloc, 2, m);

	// decrypted text
	Poly dtext(ilParams, EVALUATION, true);
// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
	ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
	ptext.SwitchFormat();
	sender.Encrypt(ilParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1); // Cin and c1 are the ciphertext

	ctCA  = ctCin.ExtractRow(0);  // CA is A^T * s + e 0,A

	receiver.EvalCT(ilParams, publicElementB, x, ctCin.ExtractRows(1, ell+1), &y, &evalCf);

	EXPECT_NO_THROW(pkg.EvalPK(ilParams, publicElementB, &evalBf));
	EXPECT_NO_THROW(pkg.KeyGen(ilParams, trapdoorA.first, evalBf, pubElemBeta, trapdoorA.second, dgg, &sk));

	Poly t(pubElemBeta);
	t.SetValuesToZero();

	for (usint i=0; i<m; i++) {
		t += (trapdoorA.first(0, i)*sk(0, i));
		t += (evalBf(0, i)*sk(1, i));
	}

	receiver.Decrypt(ilParams, sk, ctCA, evalCf, c1, &dtext);
	receiver.Decode(&dtext);

	ptext.SwitchFormat();

	EXPECT_EQ(ptext, dtext);

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

}

void UnitTestIBE(int32_t base, usint k, usint ringDimension){
	usint n = ringDimension*2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint)floor(logTwo);

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	IBE pkg, sender, receiver;

	auto pubElemA = pkg.SetupPKG(ilParams, base);

	EXPECT_NO_THROW(sender.SetupNonPKG(ilParams, base));
	EXPECT_NO_THROW(receiver.SetupNonPKG(ilParams, base));

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, m, 1);

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);
	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	// ciphertext first and second parts
	RingMat ctC0(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	Poly ctC1(dug, ilParams, EVALUATION);

	Poly u(dug, ilParams, EVALUATION);

	EXPECT_NO_THROW(pkg.KeyGen(pubElemA.first, u, pubElemA.second, dgg, &sk));

	// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
	ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
	ptext.SwitchFormat();

	EXPECT_NO_THROW(sender.Encrypt(ilParams, pubElemA.first, u, ptext, dug, &ctC0, &ctC1));

	EXPECT_NO_THROW(receiver.Decrypt(sk, ctC0, ctC1, &dtext));

	ptext.SwitchFormat();

	EXPECT_EQ(ptext,dtext);

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();
}

void UnitTestKPABEANDGate(int32_t base, usint k, usint ringDimension){

	usint n = ringDimension*2;
	usint ell = 4; // No of attributes for AND gate

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;
	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base, true);

	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE<Poly, Poly> pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x  = new usint[ell];
	x[0] = x[1] = x[2] = 0;
	usint y;

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat pubElemBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat ctCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, 2, m);

	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
	ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
	ptext.SwitchFormat();
	sender.Encrypt(ilParams, A.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

	ctCA = ctCin.ExtractRow(0);

	receiver.ANDGateEvalPK(ilParams, publicElementB.ExtractRows(1,2), &pubElemBf);
	receiver.ANDGateEvalCT(ilParams, &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf);

	pkg.KeyGen(ilParams, A.first, pubElemBf, pubElemBeta, A.second, dgg, &sk);

	receiver.Decrypt(ilParams, sk, ctCA, ctCf, c1, &dtext);
	receiver.Decode(&dtext);

	ptext.SwitchFormat();
	EXPECT_EQ(ptext, dtext);
	delete[] x;

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();
}

void UnitTesKPABENANDGATE(int32_t base, usint k, usint ringDimension){
	usint n = ringDimension*2;
	usint ell = 2; // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility<Poly>::TrapdoorGen(ilParams, SIGMA, base, true);

	Poly pubElemBeta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat ctCin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE<Poly, Poly> pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell+1];
	x[0] = x[1] = x[2] = 1;
	usint y;

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat pubElemBf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat ctCf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat ctCA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, 2, m);

	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
	ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
	ptext.SwitchFormat();

	sender.Encrypt(ilParams, A.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

	ctCA = ctCin.ExtractRow(0);

	receiver.KPABE::NANDGateEvalPK(ilParams, publicElementB.ExtractRow(0), publicElementB.ExtractRows(1,2), &pubElemBf);

	receiver.KPABE::NANDGateEvalCT(ilParams, ctCin.ExtractRow(1), &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf);

	pkg.KeyGen(ilParams, A.first, pubElemBf, pubElemBeta, A.second, dgg, &sk);

	receiver.Decrypt(ilParams, sk, ctCA, ctCf, c1, &dtext);
	receiver.Decode(&dtext);

	ptext.SwitchFormat();
	EXPECT_EQ(ptext, dtext);
	delete[] x;

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();
}

void UnitTestPolyVecDecomp(int32_t base, usint k, usint ringDimension){

	usint n = ringDimension*2;   // cyclotomic order

	native_int::BigInteger q = native_int::BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<native_int::BigInteger>(k,n);
	native_int::BigInteger rootOfUnity(RootOfUnity<native_int::BigInteger>(n, q));

	native_int::BigInteger nextQ = native_int::BigInteger::ONE << (k-1);
	nextQ = lbcrypto::NextPrime<native_int::BigInteger>(q, n);
	native_int::BigInteger nextRootOfUnity(RootOfUnity<native_int::BigInteger>(n, nextQ));

	usint m = k + k +2;

	std::vector<native_int::BigInteger> moduli;
	std::vector<native_int::BigInteger> roots_Of_Unity;
	moduli.reserve(2);
	roots_Of_Unity.reserve(2);

	moduli.push_back(q);
	moduli.push_back(nextQ);

	roots_Of_Unity.push_back(rootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity);

	BigInteger bigModulus("1");
	long double qDouble = q.ConvertToDouble();
	long double nextQdouble = nextQ.ConvertToDouble();

	bigModulus = BigInteger(qDouble)* BigInteger(nextQdouble);

	BigInteger bigRootOfUnity(RootOfUnity(n,bigModulus));

	shared_ptr<ILDCRTParams<BigInteger>> params(new ILDCRTParams<BigInteger>(n, moduli, roots_Of_Unity));
	shared_ptr<ILParams> ilParams(new ILParams(n, bigModulus, bigRootOfUnity));

	auto zero_alloc_poly = Poly::MakeAllocator(ilParams, COEFFICIENT);
	auto zero_alloc = DCRTPoly::MakeAllocator(params, COEFFICIENT);
	auto zero_alloc_eval = DCRTPoly::MakeAllocator(params, EVALUATION);

	RingMatDCRT matrixTobeDecomposed(zero_alloc, 1, m);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();

	for (usint i = 0; i < matrixTobeDecomposed.GetRows(); i++)
		for (usint j = 0; j < matrixTobeDecomposed.GetCols(); j++) {
			if(matrixTobeDecomposed(i, j).GetFormat() != COEFFICIENT)
				matrixTobeDecomposed(i,j).SwitchFormat();
				matrixTobeDecomposed(i,j) = DCRTPoly(dug, params, COEFFICIENT);
				matrixTobeDecomposed(i, j).SwitchFormat(); // always kept in EVALUATION format
			}

	RingMatDCRT results(zero_alloc_eval, 1, m);
	RingMatDCRT g = RingMatDCRT(zero_alloc_eval, 1, m).GadgetVector(base);

	RingMatDCRT psiDCRT(zero_alloc, m, m);
	RingMat psi(zero_alloc_poly, m, m);

	RingMat matrixDecomposePoly(zero_alloc_poly, 1, m);

	for(usint i = 0; i < m; i++){
		matrixDecomposePoly(0,i) = matrixTobeDecomposed(0,i).CRTInterpolate();
	}

	lbcrypto::PolyVec2BalDecom(ilParams, base, k+k, matrixDecomposePoly, &psi);

	for(usint i = 0; i < psi.GetRows(); i++){
				for(usint j = 0; j < psi.GetCols();j++){
					DCRTPoly temp(psi(i,j), params);
					psiDCRT(i,j) = temp;
				}
			}

	psiDCRT.SwitchFormat();

	results = g * psiDCRT;



	for(usint i = 0; i < results.GetRows(); i++){
		for(usint j =0; j < results.GetCols(); j++){
			EXPECT_EQ(results(i,j), matrixTobeDecomposed(i,j));
		}
	}

}

void UnitTestKPABEANDGateDCRT(int32_t base, usint ringDimension){

	usint n = ringDimension * 2;   // cyclotomic order
	usint ell = 4; // No of attributes
	native_int::BigInteger q("2101249");

	native_int::BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val - 1.0) / log(base) + 1.0;
	size_t k_ = (usint)floor(logTwo) + 1; //  (+1) is For NAF

	native_int::BigInteger nextQ("2236417");

	native_int::BigInteger nextRootOfUnity(RootOfUnity<native_int::BigInteger>(n, nextQ));

	native_int::BigInteger nextQ2("2277377");
	native_int::BigInteger nextRootOfUnity2(RootOfUnity<native_int::BigInteger>(n, nextQ2));

	usint m = 3 *  k_ + 2;

	std::vector<native_int::BigInteger> moduli;
	std::vector<native_int::BigInteger> roots_Of_Unity;
	moduli.reserve(3);
	roots_Of_Unity.reserve(3);

	moduli.push_back(q);
	moduli.push_back(nextQ);
	moduli.push_back(nextQ2);

	roots_Of_Unity.push_back(rootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity2);


	BigInteger bigModulus = BigInteger("2101249") * BigInteger("2236417") * BigInteger("2277377");

	BigInteger bigRootOfUnity(RootOfUnity(n,bigModulus));

	BinaryUniformGenerator bug = BinaryUniformGenerator();

	shared_ptr<ILDCRTParams<BigInteger>> ilDCRTParams(new ILDCRTParams<BigInteger>(n, moduli, roots_Of_Unity));

	shared_ptr<ILParams> ilParamsConsolidated(new ILParams(n, bigModulus, bigRootOfUnity));

	auto zero_alloc = DCRTPoly::MakeAllocator(ilDCRTParams, COEFFICIENT);

	DCRTPoly::DggType dgg = DCRTPoly::DggType(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();

	// Trapdoor Generation
	std::pair<RingMatDCRT, RLWETrapdoorPair<DCRTPoly>> trapdoorA = RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(ilDCRTParams, SIGMA, base, true); // A.first is the public element

	DCRTPoly pubElemBeta(dug, ilDCRTParams, EVALUATION);

	RingMatDCRT publicElementB(zero_alloc, ell + 1, m);
	RingMatDCRT ctCin(zero_alloc, ell + 2, m);
	DCRTPoly c1(dug, ilDCRTParams, EVALUATION);

	KPABE<DCRTPoly, Poly> pkg, sender, receiver;

	pkg.Setup(ilDCRTParams, base, ell, dug, &publicElementB);
	sender.Setup(ilDCRTParams, base, ell);
	receiver.Setup(ilDCRTParams, base, ell);


	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x  = new usint[ell];
	x[0] = x[1] = x[2] = 0;
	usint y;

	Poly ptext1(ilParamsConsolidated, COEFFICIENT, true);
	ptext1.SetValues(bug.GenerateVector(ringDimension, bigModulus), COEFFICIENT);

	DCRTPoly ptext(ptext1, ilDCRTParams);

	// circuit outputs
	RingMatDCRT pubElemBf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  //evaluated Bs
	RingMatDCRT ctCf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  // evaluated Cs
	RingMatDCRT ctCA(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m); // CA

																   // secret key corresponding to the circuit output
	RingMatDCRT sk(zero_alloc, 2, m);

	// decrypted text
	DCRTPoly dtext(ilDCRTParams, EVALUATION, true);

	ptext.SwitchFormat();

	sender.Encrypt(ilDCRTParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

	ctCA = ctCin.ExtractRow(0);

	receiver.ANDGateEvalPKDCRT(ilDCRTParams, publicElementB.ExtractRows(1,2), &pubElemBf, ilParamsConsolidated);
	receiver.ANDGateEvalCTDCRT(ilDCRTParams, &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf, ilParamsConsolidated);

	pkg.KeyGen(ilDCRTParams, trapdoorA.first, pubElemBf, pubElemBeta,trapdoorA.second, dgg, &sk);

	receiver.Decrypt(ilDCRTParams, sk, ctCA, ctCf, c1, &dtext);

	Poly dtextPoly(dtext.CRTInterpolate());

	receiver.Decode(&dtextPoly);

	ptext.SwitchFormat();
	EXPECT_EQ(ptext1.GetValues(), dtextPoly.GetValues());
	delete[] x;

}

void UnitTesKPABENANDGATEDCRT(int32_t base, usint ringDimension){
	usint n = ringDimension * 2;   // cyclotomic order
	usint ell = 4; // No of attributes
	native_int::BigInteger q("2101249");

	native_int::BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val - 1.0) / log(base) + 1.0;
	size_t k_ = (usint)floor(logTwo) + 1; //  (+1) is For NAF

	native_int::BigInteger nextQ("2236417");

	native_int::BigInteger nextRootOfUnity(RootOfUnity<native_int::BigInteger>(n, nextQ));

	native_int::BigInteger nextQ2("2277377");
	native_int::BigInteger nextRootOfUnity2(RootOfUnity<native_int::BigInteger>(n, nextQ2));

	usint m = 3 *  k_ + 2;

	std::vector<native_int::BigInteger> moduli;
	std::vector<native_int::BigInteger> roots_Of_Unity;
	moduli.reserve(3);
	roots_Of_Unity.reserve(3);

	moduli.push_back(q);
	moduli.push_back(nextQ);
	moduli.push_back(nextQ2);

	roots_Of_Unity.push_back(rootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity);
	roots_Of_Unity.push_back(nextRootOfUnity2);


	BigInteger bigModulus = BigInteger("2101249") * BigInteger("2236417") * BigInteger("2277377");

	BigInteger bigRootOfUnity(RootOfUnity(n,bigModulus));

	BinaryUniformGenerator bug = BinaryUniformGenerator();


	shared_ptr<ILDCRTParams<BigInteger>> ilDCRTParams(new ILDCRTParams<BigInteger>(n, moduli, roots_Of_Unity));

	shared_ptr<ILParams> ilParamsConsolidated(new ILParams(n, bigModulus, bigRootOfUnity));

	auto zero_alloc = DCRTPoly::MakeAllocator(ilDCRTParams, COEFFICIENT);

	DCRTPoly::DggType dgg = DCRTPoly::DggType(SIGMA);
	DCRTPoly::DugType dug = DCRTPoly::DugType();

	// Trapdoor Generation
	std::pair<RingMatDCRT, RLWETrapdoorPair<DCRTPoly>> trapdoorA = RLWETrapdoorUtility<DCRTPoly>::TrapdoorGen(ilDCRTParams, SIGMA, base, true); // A.first is the public element

	DCRTPoly pubElemBeta(dug, ilDCRTParams, EVALUATION);

	RingMatDCRT publicElementB(zero_alloc, ell + 1, m);
	RingMatDCRT ctCin(zero_alloc, ell + 2, m);
	DCRTPoly c1(dug, ilDCRTParams, EVALUATION);

	KPABE<DCRTPoly, Poly> pkg, sender, receiver;

	pkg.Setup(ilDCRTParams, base, ell, dug, &publicElementB);
	sender.Setup(ilDCRTParams, base, ell);
	receiver.Setup(ilDCRTParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell+1];
	x[0] = x[1] = x[2] = 1;
	usint y;

	Poly ptext1(ilParamsConsolidated, COEFFICIENT, true);
	ptext1.SetValues(bug.GenerateVector(ringDimension, bigModulus), COEFFICIENT);

	DCRTPoly ptext(ptext1, ilDCRTParams);

	// circuit outputs
	RingMatDCRT pubElemBf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  //evaluated Bs
	RingMatDCRT ctCf(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m);  // evaluated Cs
	RingMatDCRT ctCA(DCRTPoly::MakeAllocator(ilDCRTParams, EVALUATION), 1, m); // CA

																   // secret key corresponding to the circuit output
	RingMatDCRT sk(zero_alloc, 2, m);

	// decrypted text
	DCRTPoly dtext(ilDCRTParams, EVALUATION, true);

	ptext.SwitchFormat();

	sender.Encrypt(ilDCRTParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1);

	ctCA = ctCin.ExtractRow(0);

	receiver.NANDGateEvalPKDCRT(ilDCRTParams, publicElementB.ExtractRow(0), publicElementB.ExtractRows(1,2), &pubElemBf, ilParamsConsolidated);

	receiver.NANDGateEvalCTDCRT(ilDCRTParams, ctCin.ExtractRow(1), &x[1], publicElementB.ExtractRows(1,2), ctCin.ExtractRows(2,3), &y, &ctCf, ilParamsConsolidated);

	pkg.KeyGen(ilDCRTParams, trapdoorA.first, pubElemBf, pubElemBeta,trapdoorA.second, dgg, &sk);

	receiver.Decrypt(ilDCRTParams, sk, ctCA, ctCf, c1, &dtext);

	Poly dtextPoly(dtext.CRTInterpolate());

	receiver.Decode(&dtextPoly);

	ptext.SwitchFormat();
	EXPECT_EQ(ptext1.GetValues(),  dtextPoly.GetValues());
	delete[] x;
}

TEST(UTABE, cp_abe_base_32) {
	UnitTestCPABE(32,34, 1024);
}

TEST(UTABE, kp_abe_benchmarkcircuit_base_32) {
	UnitTestKPABEBenchMarkCircuit(32,51, 2048);
}

TEST(UTABE, kp_abe_andgate_base_32) {
	UnitTestKPABEANDGate(32,51,2048);
}

TEST(UTABE, kp_abe_nandgate_base_32) {
	UnitTesKPABENANDGATE(32,51,2048);
}

TEST(UTABE, ibe_base_32) {
	UnitTestIBE(32,34,1024);
}

TEST(UTABE, polyVecBalDecompose_base_32) {
	UnitTestPolyVecDecomp(32,32,1024);
}

TEST(UTABE, kp_abe_andgate_dcrt){
	UnitTestKPABEANDGateDCRT(32, 2048);
}

TEST(UTABE, kp_abe_nandgate_dcrt){
	UnitTesKPABENANDGATEDCRT(32, 2048);
}
