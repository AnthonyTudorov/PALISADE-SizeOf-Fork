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

#include "../lib/cryptocontext.h"
#include "../lib/abe/cp_abe.h"
#include "../lib/abe/kp_abe.h"
#include "../lib/abe/ibe.h"

#include "lattice/elemparamfactory.h"

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
			usint ell = 32;

			BigInteger q = BigInteger::ONE << (k-1);
			q = lbcrypto::FirstPrime<BigInteger>(k,n);
			BigInteger rootOfUnity(RootOfUnity(n, q));

			double val = q.ConvertToDouble();
			double logTwo = log(val-1.0)/log(base)+1.0;
			size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */

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
		//	usint *s = new usint[ell];

			usint s[ell];
			// Access structure
			int w[ell];

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

				EXPECT_NO_THROW(sender.Encrypt(ilParams, trapdoor.first, pubElemBPos, pubElemBNeg, u, w, ptext, dgg, dug, bug, &ctW, &ctCPos, &nC, &c1));


				EXPECT_NO_THROW(receiver.Decrypt(ilParams, w, s, sk, ctW, ctCPos, nC, c1, &dtext));

				ptext.SwitchFormat();

				EXPECT_EQ(ptext,dtext);

				ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();
}

void UnitTestKPABE(int32_t base, usint k, usint ringDimension){
		usint n = ringDimension*2;   // cyclotomic order
		usint ell = 8; // No of attributes for NAND gate

		BigInteger q = BigInteger::ONE << (k-1);
		q = lbcrypto::FirstPrime<BigInteger>(k,n);
		BigInteger rootOfUnity(RootOfUnity(n, q));

		double val = q.ConvertToDouble();
		double logTwo = log(val-1.0)/log(base)+1.0;
		size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */

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
		std::pair<RingMat, RLWETrapdoorPair<Poly>> trapdoorA = RLWETrapdoorUtility::TrapdoorGen(ilParams, SIGMA, base, true); // A.first is the public element

		Poly pubElemBeta(dug, ilParams, EVALUATION);

		RingMat publicElementB(zero_alloc, ell+1, m);
		RingMat ctCin(zero_alloc, ell+2, m);
		Poly c1(dug, ilParams, EVALUATION);

		KPABE pkg, sender, receiver;

		EXPECT_NO_THROW(pkg.Setup(ilParams, base, ell, dug, &publicElementB));
		EXPECT_NO_THROW(sender.Setup(ilParams, base, ell));
		EXPECT_NO_THROW(receiver.Setup(ilParams, base, ell));

		usint x[] = {1,1,0,1,1,1,1,0,0}; // array of attributes, everything is set to 1 for NAND gate evaluation, values set based on experimental results

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
		EXPECT_NO_THROW(sender.Encrypt(ilParams, trapdoorA.first, publicElementB, pubElemBeta, x, ptext, dgg, dug, bug, &ctCin, &c1)); // Cin and c1 are the ciphertext

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

		EXPECT_EQ(t,pubElemBeta);//testing keygen

		EXPECT_NO_THROW(receiver.Decrypt(ilParams, sk, ctCA, evalCf, c1, &dtext));

		ptext.SwitchFormat();
		EXPECT_EQ(ptext,dtext);

		ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

}

void UnitTestIBE(int32_t base, usint k, usint ringDimension){
	usint n = ringDimension*2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */

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

	auto pubElemA = pkg.Setup(ilParams, base, dug);

	EXPECT_NO_THROW(sender.Setup(ilParams, base));
	EXPECT_NO_THROW(receiver.Setup(ilParams, base));

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

	EXPECT_NO_THROW(pkg.KeyGen(ilParams, pubElemA.first, u, pubElemA.second, dgg, &sk));

	// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
	ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
	ptext.SwitchFormat();

	EXPECT_NO_THROW(sender.Encrypt(ilParams, pubElemA.first, u, ptext, dgg, dug, bug, &ctC0, &ctC1));

	EXPECT_NO_THROW(receiver.Decrypt(ilParams, sk, ctC0, ctC1, &dtext));

	ptext.SwitchFormat();

	EXPECT_EQ(ptext,dtext);

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();
}

TEST(UTABE, cp_abe_base_2) {
	UnitTestCPABE(2,34, 1024);
}

TEST(UTABE, cp_abe_base_4) {
	UnitTestCPABE(4,34, 1024);
}

TEST(UTABE, cp_abe_base_16) {
	UnitTestCPABE(16,34, 1024);
}

TEST(UTABE, kp_abe_base_2) {
	UnitTestKPABE(2,51, 1024);
}

TEST(UTABE, kp_abe_base_4) {
	UnitTestKPABE(4,51, 2048);
}

TEST(UTABE, kp_abe_base_16) {
	UnitTestKPABE(8,51, 2048);
}

TEST(UTABE, ibe_base_2) {
	UnitTestIBE(2,36,1024);
}

TEST(UTABE, ibe_base_4) {
	UnitTestIBE(4,36,1024);
}

TEST(UTABE, ibe_base_16) {
	UnitTestIBE(16,51,2048);
}
