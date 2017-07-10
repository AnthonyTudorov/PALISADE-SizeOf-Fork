//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.03
Last Edited:
12/22/2016
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Dr. David Cousins, dcousins@bbn.com

Description:

This is a highly simplified version of ObfuscateSimulator.cpp used for debugging.
License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#define PROFILE  //define this to enable PROFILELOG and TIC/TOC
// Note must must be before all headers

#include <iostream>
#include <fstream>
//#include "obfuscation/lweconjunctionobfuscatev3.h"
//#include "obfuscation/lweconjunctionobfuscatev3.cpp"
#include "KP_ABE.h"

#include "utils/debug.h"

#include <omp.h> //open MP header

//using namespace std;
using namespace lbcrypto;


int TestBalDecomp (usint iter, int32_t base)
{
	usint N = 2048;
	usint n = N*2;
	size_t k_ = 40;

	BigInteger q = BigInteger::ONE << (k_-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));
//	BigInteger q1 = q-BigInteger::ONE;

	size_t k = k_ + 1;

	if(q.GetLengthForBase(2) != k_) {
		std::cout << "Bit size is not supported!" <<std::endl;
		return -1;
	}

	std::cout << "Modulus and its bit size: " << q << " " << q.GetLengthForBase(2) << std::endl;
	std::cout << "Ring dimension: " << N << std::endl;

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	k = (usint) floor(logTwo) + 1;
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	size_t m = k+2;


	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	RingMat B(zero_alloc, 1, m);
	RingMat Psi(zero_alloc, m, m);

	for(usint i = 0; i<m; i++) {
		for(usint j=0; j<m; j++) {
			Psi(i, j).SetValues(bug.GenerateVector(N, q), COEFFICIENT);
		}
	}

	/* Generate uniformly random polynomial vectors */
	for (usint j = 0; j < B.GetCols(); j++) {
		if(B(0, j).GetFormat() != COEFFICIENT)
			B(0, j).SwitchFormat();
		B(0, j).SetValues(dug.GenerateVector(N), COEFFICIENT); // always sample in COEFFICIENT format
		B(0, j).SwitchFormat(); // always kept in EVALUATION format
	}

	// for timing
	double start, finish;

	start = currentDateTime();

	polyVec2BalDecom (ilParams, base, k, B, Psi);

	finish = currentDateTime();

	std::cout << "Balanced Decomposition : " << "\t" << (finish - start) << " ms" << std::endl;

	// Check the correctness
	RingMat BReComp(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat G = RingMat(Poly::MakeAllocator(ilParams, EVALUATION), 1, k).GadgetVector(base);

	for(usint i=0; i<m; i++) {
		for (usint j=0; j<k; j++) {
			BReComp(0, i) += G(0, j)*Psi(j, i);
		}
	}

	//std::cout << "B(1): " << B(0, 1) << std::endl;
	//std::cout << "BR(1): " << BReComp(0, 1) << std::endl;

	if(B == BReComp)
		std::cout << "Success!\n";
	else
		std::cout << "Failure!\n";

	std::cout << "Do the same thing with the old routines\n";

	std::vector<Poly> digitsC1(m);
	start = currentDateTime();
	for (usint j = 0; j < m; j++) {
		digitsC1 = B(0, j).BaseDecompose(1);
		for (usint k = 0; k < k; k++)
			Psi(k, j) = digitsC1[k];
		Psi(m-2, j).SetValuesToZero();
		Psi(m-1, j).SetValuesToZero();
	}
	finish = currentDateTime();

	std::cout << "Bit Decomposition - old : " << "\t" << (finish - start) << " ms" << std::endl;
	return 1;
}


int TestNAFDecomp (usint iter)
{
	usint N = 2048;
	usint n = N*2;
	size_t k_ = 40;

	BigInteger q = BigInteger::ONE << (k_-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));
//	BigInteger q1 = q-BigInteger::ONE;

	size_t k = k_ + 1;
	size_t m = k+2;

	if(q.GetLengthForBase(2) != k_) {
		std::cout << "Bit size is not supported!" <<std::endl;
		return -1;
	}

	std::cout << "Modulus and its bit size: " << q << " " << q.GetLengthForBase(2) << std::endl;
	std::cout << "Ring dimension: " << N << std::endl;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	RingMat B(zero_alloc, 1, m);
	RingMat Psi(zero_alloc, m, m);

	for(usint i = 0; i<m; i++) {
		for(usint j=0; j<m; j++) {
			Psi(i, j).SetValues(bug.GenerateVector(N, q), COEFFICIENT);
		}
	}

	/* Generate uniformly random polynomial vectors */
	for (usint j = 0; j < B.GetCols(); j++) {
		if(B(0, j).GetFormat() != COEFFICIENT)
			B(0, j).SwitchFormat();
		B(0, j).SetValues(dug.GenerateVector(N), COEFFICIENT); // always sample in COEFFICIENT format
		B(0, j).SwitchFormat(); // always kept in EVALUATION format
	}

	// for timing
	double start, finish;

	start = currentDateTime();

	polyVec2NAFDecom (ilParams, k, B, Psi);

	finish = currentDateTime();

	std::cout << "Binary NAF Decomposition : " << "\t" << (finish - start) << " ms" << std::endl;

	// Check the correctness
	RingMat BReComp(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat G = RingMat(Poly::MakeAllocator(ilParams, EVALUATION), 1, k).GadgetVector();

	for(usint i=0; i<m; i++) {
		for (usint j=0; j<k; j++) {
			BReComp(0, i) += G(0, j)*Psi(j, i);
		}
	}

	//std::cout << "B(1): " << B(0, 1) << std::endl;
	//std::cout << "BR(1): " << BReComp(0, 1) << std::endl;

	if(B == BReComp)
		std::cout << "Success!\n";
	else
		std::cout << "Failure!\n";

	std::cout << "Do the same thing with the old routines\n";

	std::vector<Poly> digitsC1(m);
	start = currentDateTime();
	for (usint j = 0; j < m; j++) {
		digitsC1 = B(0, j).BaseDecompose(1);
		for (usint k = 0; k < k; k++)
			Psi(k, j) = digitsC1[k];
		Psi(m-2, j).SetValuesToZero();
		Psi(m-1, j).SetValuesToZero();
	}
	finish = currentDateTime();

	std::cout << "Bit Decomposition - old : " << "\t" << (finish - start) << " ms" << std::endl;

	return 1;
}

int BitSizes(usint depth, usint iter)
{
	usint N, k;
	int32_t base = 2;

	switch(depth) {
	case 1:
		N = 1024;
		k = 36;
		break;
	case 2:
		N = 2048;
		k = 50;
		break;
	case 3:
		N = 2048;
		k = 64;
		break;
	case 4:
		N = 4096;
		k = 88;
		break;
	case 5:
		N = 4096;
		k = 106;
		break;
	case 6:
		N = 4096;
		k = 122;
		break;
	case 7:
		N = 4096;
		k = 141;
		break;
	default:
		std::cout << "depth is too big";
		return -1;
	}
	usint n = N*2;   // cyclotomic order
	usint ell = (1 << depth); // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo);
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	if(k_ != k) {
		std::cout << "Wrong bit size!!";
		return -1;
	}

	k++;
	usint m = k+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);


	RingMat B(zero_alloc, 1, m);
	RingMat Psi(zero_alloc, m, m);

	KPABE PKG;
	RingMat sKey(zero_alloc, 2, m);
	Poly beta(dug, ilParams, EVALUATION);

	PKG.Setup(ilParams, base, ell, dug, B);
	PKG.KeyGen(ilParams, A.first, B.ExtractRow(0), beta, A.second, dgg, sKey);

	RingMat noise_init(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), 1, m);
	RingMat noise(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), depth+1, m);

	Poly dtext(dug, ilParams, EVALUATION);
	std::vector<Poly> digitsC1(m);

	double maxNorm_before = 0.0, maxNorm_after = 0.0;
	for (usint repeat=0; repeat<iter; repeat++)
	{
		std::cout << "iter no: " << repeat << std::endl;
		for (usint j = 0; j < m; j++) {
			noise_init(0, j).SetValues(dgg.GenerateVector(N, q), COEFFICIENT);
			noise_init(0, j).SwitchFormat();
		}
//multiplication of eis and sis
		for(usint si=0; si<m; si++) {
			noise(0, si).SetValuesToZero();
			for(usint sj=0; sj<m; sj++) {
				if(bug.GenerateInteger() == BigInteger::ONE)
					noise(0, si) += noise_init(0, sj);
				else
					noise(0, si) -= noise_init(0, sj);
			}
		}

		for(usint i=0; i<depth; i++) {
			std::cout << "Depth " << i+1 << std::endl;
			for (usint j = 0; j < m; j++) { // Performing bit decomposition, first loop is looping over every other Bi (as per the circuit)
				digitsC1 = B(0, j).BaseDecompose(1); // bit decomposing each polynomial in Bi, BitDecompose already gives you a vector based on least significant bit order
				for (usint kk = 0; kk < k; kk++)  // Moving the decomposed polynomial into jth column of R
					Psi(kk, j) = digitsC1[kk];
				Psi(m-2, j).SetValuesToZero();
				Psi(m-1, j).SetValuesToZero();
			}

			for (usint j = 0; j < m; j++) {
				noise(i+1, j) = noise(i, 0) * Psi(0, j);
				for (usint kk = 1; kk < m; kk++) {
					noise(i+1, j) += noise(i, kk) * Psi(kk, j);
				}
			}
			for (usint j = 0; j < m; j++) {
				B(0, j).SetValues(dug.GenerateVector(N), COEFFICIENT);
				B(0, j).SwitchFormat();
			}
		}

		dtext.SetValuesToZero();
		for(usint j=0; j<m; j++)
			dtext += noise_init(0, j)*sKey(0, j);
		for(usint j=0; j<m; j++)
			dtext += noise(depth, j)*sKey(1, j);

		if(dtext.GetFormat() == EVALUATION)
			dtext.SwitchFormat();
		for (usint j = 0; j < m; j++)
			noise(depth, j).SwitchFormat();

		for (usint j = 0; j < m; j++) {
			if (noise(depth, j).Norm() > maxNorm_before)
				maxNorm_before = noise(depth, j).Norm();
		}

		if (dtext.Norm() > maxNorm_after)
			maxNorm_after = dtext.Norm();

		if(dtext.GetFormat() == COEFFICIENT)
			dtext.SwitchFormat();
		for (usint j = 0; j < m; j++)
			noise(depth, j).SwitchFormat();
	}

	std::cout << "Error norm on depth before multiplication with secret key" << ":: " << maxNorm_before << "\t" << log2(maxNorm_before) << std::endl;
	std::cout << "Max norm after multiplication with secret key: " << log2(maxNorm_after) << std::endl;

	return 0;
}

int BitSizeswNAFDecompose(usint depth, usint iter)
{
	usint N, k;
	int32_t base = 2;

	switch(depth) {
	case 1:
		N = 1024;
		k = 36;
		break;
	case 2:
		N = 2048;
		k = 51;
		break;
	case 3:
		N = 2048;
		k = 60;
		break;
	case 4:
		N = 2048;
		k = 69;
		break;
	case 5:
		N = 4096;
		k = 82;
		break;
	case 6:
		N = 4096;
		k = 92;
		break;
	case 7:
		N = 4096;
		k = 102;
		break;
	case 8:
		N = 4096;
		k = 111;
		break;
	case 9:
		N = 4096;
		k = 122;
		break;
	case 10:
		N = 4096;
		k = 132;
		break;
	default:
		std::cout << "depth is too big";
		return -1;
	}
	usint n = N*2;   // cyclotomic order
	usint ell = (1 << depth); // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo);
	std::cout << "q: " << q << std::endl;
	std::cout << "Modulus length: " << k_ << std::endl;
	std::cout << "Ring dimension: " << N << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	if(k_ != k) {
		std::cout << "Wrong bit size!!";
		return -1;
	}

	k++;  /* For NAF */
	usint m = k+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);


	RingMat B(zero_alloc, 1, m);
	RingMat Psi(zero_alloc, m, m);

	KPABE PKG;
	RingMat sKey(zero_alloc, 2, m);
	Poly beta(dug, ilParams, EVALUATION);

	PKG.Setup(ilParams, base, ell, dug, B);
	PKG.KeyGen(ilParams, A.first, B.ExtractRow(0), beta, A.second, dgg, sKey);

	RingMat noise_init(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), 1, m);
	RingMat noise(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), depth+1, m);

	Poly dtext(dug, ilParams, EVALUATION);
	std::vector<Poly> digitsC1(m);

	double maxNorm_before = 0.0, maxNorm_after = 0.0;
	for (usint repeat=0; repeat<iter; repeat++)
	{
		std::cout << "iter no: " << repeat << std::endl;
		for (usint j = 0; j < m; j++) {
			noise_init(0, j).SetValues(dgg.GenerateVector(N, q), COEFFICIENT);
			noise_init(0, j).SwitchFormat();
		}
//multiplication of eis and sis
		for(usint si=0; si<m; si++) {
			noise(0, si).SetValuesToZero();
			for(usint sj=0; sj<m; sj++) {
				if(bug.GenerateInteger() == BigInteger::ONE)
					noise(0, si) += noise_init(0, sj);
				else
					noise(0, si) -= noise_init(0, sj);
			}
		}

		for(usint i=0; i<depth; i++) {
			std::cout << "Depth " << i+1 << std::endl;
			polyVec2NAFDecom (ilParams, k, B, Psi);
			/*for (usint j = 0; j < m; j++) { // Performing bit decomposition, first loop is looping over every other Bi (as per the circuit)
				digitsC1 = B(0, j).BaseDecompose(1); // bit decomposing each polynomial in Bi, BitDecompose already gives you a vector based on least significant bit order
				for (usint kk = 0; kk < k; kk++)  // Moving the decomposed polynomial into jth column of R
					Psi(kk, j) = digitsC1[kk];
				Psi(m-2, j).SetValuesToZero();
				Psi(m-1, j).SetValuesToZero();
			}*/

			for (usint j = 0; j < m; j++) {
				noise(i+1, j) = noise(i, 0) * Psi(0, j);
				for (usint kk = 1; kk < m; kk++) {
					noise(i+1, j) += noise(i, kk) * Psi(kk, j);
				}
			}
			for (usint j = 0; j < m; j++) {
				B(0, j).SetValues(dug.GenerateVector(N), COEFFICIENT);
				B(0, j).SwitchFormat();
			}
		}

		dtext.SetValuesToZero();
		for(usint j=0; j<m; j++)
			dtext += noise_init(0, j)*sKey(0, j);
		for(usint j=0; j<m; j++)
			dtext += noise(depth, j)*sKey(1, j);

		if(dtext.GetFormat() == EVALUATION)
			dtext.SwitchFormat();
		for (usint j = 0; j < m; j++)
			noise(depth, j).SwitchFormat();

		for (usint j = 0; j < m; j++) {
			if (noise(depth, j).Norm() > maxNorm_before)
				maxNorm_before = noise(depth, j).Norm();
		}

		if (dtext.Norm() > maxNorm_after)
			maxNorm_after = dtext.Norm();

		if(dtext.GetFormat() == COEFFICIENT)
			dtext.SwitchFormat();
		for (usint j = 0; j < m; j++)
			noise(depth, j).SwitchFormat();

		std::cout << "Error norm on depth before multiplication with secret key: " << log2(maxNorm_before) << std::endl;
		std::cout << "Max norm after multiplication with secret key: " << log2(maxNorm_after) << std::endl;
	}

	std::cout << "Error norm on depth before multiplication with secret key" << ":: " << maxNorm_before << "\t" << log2(maxNorm_before) << std::endl;
	std::cout << "Max norm after multiplication with secret key: " << log2(maxNorm_after) << std::endl;

	return 0;
}


int BitSizesBinaryDecompose(usint depth, usint iter)
{
	usint N, k;
	int32_t base = 2;

	switch(depth) {
	case 1:
		N = 1024;
		k = 36;
		break;
	case 2:
		N = 2048;
		k = 51;
		break;
	case 3:
		N = 2048;
		k = 60;
		break;
	case 4:
		N = 2048;
		k = 69;
		break;
	case 5:
		N = 4096;
		k = 82;
		break;
	case 6:
		N = 4096;
		k = 92;
		break;
	case 7:
		N = 4096;
		k = 102;
		break;
	case 8:
		N = 4096;
		k = 114;
		break;
	default:
		std::cout << "depth is too big";
		return -1;
	}
	usint n = N*2;   // cyclotomic order
	usint ell = (1 << depth); // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo);
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	usint m = k_+2;
	if(k_ != k) {
		std::cout << "Wrong bit size!!";
		return -1;
	}

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);

	RingMat B(zero_alloc, 1, m);
	RingMat Psi(zero_alloc, m, m);

	KPABE PKG;
	RingMat sKey(zero_alloc, 2, m);
	Poly beta(dug, ilParams, EVALUATION);

	PKG.Setup(ilParams, base, ell, dug, B);
	PKG.KeyGen(ilParams, A.first, B.ExtractRow(0), beta, A.second, dgg, sKey);

	RingMat noise_init(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), 1, m);
	RingMat noise(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), depth+1, m);

	Poly dtext(dug, ilParams, EVALUATION);
	std::vector<Poly> digitsC1(m);

	double maxNorm_before = 0.0, maxNorm_after = 0.0;
	for (usint repeat=0; repeat<iter; repeat++)
	{
		std::cout << "iter no: " << repeat << std::endl;
		for (usint j = 0; j < m; j++) {
			noise_init(0, j).SetValues(dgg.GenerateVector(N, q), COEFFICIENT);
			noise_init(0, j).SwitchFormat();
		}
//multiplication of eis and sis
		for(usint si=0; si<m; si++) {
			noise(0, si).SetValuesToZero();
			for(usint sj=0; sj<m; sj++) {
				if(bug.GenerateInteger() == BigInteger::ONE)
					noise(0, si) += noise_init(0, sj);
				else
					noise(0, si) -= noise_init(0, sj);
			}
		}

		for(usint i=0; i<depth; i++) {
			std::cout << "Depth " << i+1 << std::endl;
			for (usint j = 0; j < m; j++) { // Performing bit decomposition, first loop is looping over every other Bi (as per the circuit)
//			digitsC1 = B(0, j).BinaryBaseDecompose(1); // bit decomposing each polynomial in Bi, BitDecompose already gives you a vector based on least significant bit order
			digitsC1 = B(0, j).BaseDecompose(1);
			for (usint kk = 0; kk < k; kk++)  // Moving the decomposed polynomial into jth column of R
					Psi(kk, j) = digitsC1[kk];
				Psi(m-2, j).SetValuesToZero();
				Psi(m-1, j).SetValuesToZero();
			}

			for (usint j = 0; j < m; j++) {
				noise(i+1, j) = noise(i, 0) * Psi(0, j);
				for (usint kk = 1; kk < m; kk++) {
					noise(i+1, j) += noise(i, kk) * Psi(kk, j);
				}
			}
			for (usint j = 0; j < m; j++) {
				B(0, j).SetValues(dug.GenerateVector(N), COEFFICIENT);
				B(0, j).SwitchFormat();
			}
		}

		dtext.SetValuesToZero();
		for(usint j=0; j<m; j++)
			dtext += noise_init(0, j)*sKey(0, j);
		for(usint j=0; j<m; j++)
			dtext += noise(depth, j)*sKey(1, j);

		if(dtext.GetFormat() == EVALUATION)
			dtext.SwitchFormat();
		for (usint j = 0; j < m; j++)
			noise(depth, j).SwitchFormat();

		for (usint j = 0; j < m; j++) {
			if (noise(depth, j).Norm() > maxNorm_before)
				maxNorm_before = noise(depth, j).Norm();
		}

		if (dtext.Norm() > maxNorm_after)
			maxNorm_after = dtext.Norm();

		if(dtext.GetFormat() == COEFFICIENT)
			dtext.SwitchFormat();
		for (usint j = 0; j < m; j++)
			noise(depth, j).SwitchFormat();

		std::cout << "Error norm on depth before multiplication with secret key: " << log2(maxNorm_before) << std::endl;
		std::cout << "Max norm after multiplication with secret key: " << log2(maxNorm_after) << std::endl;
	}

	std::cout << "Error norm on depth before multiplication with secret key" << ":: " << maxNorm_before << "\t" << log2(maxNorm_before) << std::endl;
	std::cout << "Max norm after multiplication with secret key: " << log2(maxNorm_after) << std::endl;

	return 0;
}

int Poly2NAFDecompose(usint iter)
{
	usint N = 2048;
	usint n = N*2;
	size_t k_ = 40;

	auto Big0 = BigInteger::ZERO;
	auto Big1 = BigInteger::ONE;
	auto Big2 = BigInteger::TWO;
	auto Big4 = BigInteger::FOUR;


	BigInteger q = BigInteger::ONE << (k_-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));
	BigInteger q1 = q-BigInteger::ONE;

	size_t k = k_ + 1;

	if(q.GetLengthForBase(2) != k_) {
		std::cout << "Bit size is not supported!" <<std::endl;
		return -1;
	}

	std::cout << "Modulus and its bit size: " << q << " " << q.GetLengthForBase(2) << std::endl;
	std::cout << "Ring dimension: " << N << std::endl;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	Poly poly(dug, ilParams, COEFFICIENT);

	RingMat G = RingMat(zero_alloc, 1, k).GadgetVector();

	RingMat polyDecomp(zero_alloc, 1, k);
	int k_i;
	for(usint i=0; i<N; i++) {
		auto coeff_i = poly.GetValAtIndex(i);
		//std::cout << "coeff(" << i << "): " << coeff_i << std::endl;

		int j = 0;
		while(coeff_i > Big0) {
			k_i = coeff_i.GetBitAtIndex(1);

			if(k_i == 1) {
				k_i = 2 - coeff_i.Mod(Big4).ConvertToInt();
				if(k_i == 1)
					coeff_i = coeff_i - Big1;
				else
					coeff_i = coeff_i + Big1;
			}
			else
				k_i = 0;

			coeff_i = coeff_i.DividedBy(Big2);
			if(k_i == 1)
				polyDecomp(0, j).SetValAtIndex(i, Big1);
			else if(k_i == -1)
				polyDecomp(0, j).SetValAtIndex(i, q1);
			else
				polyDecomp(0, j).SetValAtIndex(i, Big0);
			j++;
		}
	}

	//std::cout << "poly: " << poly << std::endl;
	//std::cout << "Poly Decomp 0: " << PolyDecomp(0, 0);

	Poly polyRecomp(dug, ilParams, COEFFICIENT);
	polyRecomp.SetValuesToZero();

	for(usint i=0; i<k; i++) {
		polyRecomp = polyRecomp + G(0, i)*polyDecomp(0, i);
	}
	//std::cout << "poly recomposed: " << PolyRecomp << std::endl;

	if(poly == polyRecomp)
		std::cout << "Success!!\n";
	else
		std::cout << "Failure!!\n";

	return 0;
}


int Decompose_Experiments (usint base)
{
	usint N = 32;
	usint n = N*2;
	size_t k = 30;
	BigInteger q = BigInteger::ONE << (k-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));
	BigInteger q1 = q-BigInteger::ONE;

//	DiscreteUniformGenerator dug = DiscreteUniformGenerator(q);

	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);

	BigInteger sayi(dug.GenerateInteger());
	//BigInteger sayi("13");
	//sayi = sayi*BigInteger::TWO;

	std::cout << "modulus: " << q << "\t" << q.GetLengthForBase(2) << std::endl;
	std::cout << "sayi: " << sayi << "\t" << sayi.GetLengthForBase(2) << std::endl;

	BigInteger tmp(sayi);
	usint nBits = k+1;
	int ki;
	vector<BigInteger> kDecomp;
	kDecomp.reserve(nBits);

	while(tmp > BigInteger::ZERO) {
		ki = tmp.GetBitAtIndex(1);
		if(ki == 1) {
			ki = 2 - tmp.Mod(BigInteger::FOUR).ConvertToInt();
			if(ki == 1)
				tmp = tmp - BigInteger::ONE;
			else
				tmp = tmp + BigInteger::ONE;
		}
		else
			ki = 0;
		tmp = tmp.DividedBy(BigInteger::TWO);
		if(ki == 1)
			kDecomp.push_back(BigInteger::ONE);
		else if(ki == -1)
			kDecomp.push_back(q1);
		else
			kDecomp.push_back(BigInteger::ZERO);
	}

	std::cout << "NAF length: " <<kDecomp.size() << std::endl;
	/*for(auto& i : kDecomp)
		std::cout << i << " ";*/

	vector<BigInteger> g;
	kDecomp.reserve(nBits);

	BigInteger twoPow(BigInteger::TWO);
	g.push_back(BigInteger::ONE);
	for (usint i=1; i<nBits; i++) {
		g.push_back(twoPow);
		twoPow = twoPow * BigInteger::TWO;
		twoPow.Mod(q);
	}

/*	std::cout << "\nGadget matrix:\n";
	for(auto& i : g)
		std::cout << i << " ";
	std::cout << std::endl;*/

	BigInteger kRecomp(BigInteger::ZERO);

	for (usint i=0; i<kDecomp.size(); i++)
		kRecomp += g[i]*kDecomp[i];

	kRecomp = kRecomp.Mod(q);
	std::cout << "kRecomp: " << kRecomp << std::endl;

	if(sayi.Mod(q) == kRecomp)
		std::cout << "Success!\n";
	else
		std::cout << "Failure!\n";

	return 0;
}

#if 0
int ErrorRatesSi(usint argc)
{
	usint n = 4;
	usint N = n/2;
	usint k = 30;
	usint ell = 2; // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(2)+1.0;
	size_t k_ = (usint) floor(logTwo);
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	usint m = k_+2;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	RingMat eA(Poly::MakeDiscreteGaussianCoefficientAllocator(ilParams, EVALUATION, SIGMA), m, 1);
	RingMat ei(Poly::MakeAllocator(ilParams, EVALUATION), m, 1);

	for(usint i=0; i<m; i++) {
		for(usint j=0; j<m; j++) {
			if(bug.GenerateInteger()==BigInteger::ONE)
				ei(i, 0) += eA(j,0);
			else
				ei(i, 0) -= eA(j,0);
		}
	}

	eA.SwitchFormat();
	std::cout << "Initial error norm: " << eA.Norm() << std::endl;
	ei.SwitchFormat();
	std::cout << "Final error norm: " << ei.Norm() << std::endl;

	int size=4;
	RingMat vektor(Poly::MakeAllocator(ilParams, EVALUATION), size, size);

	for(usint i=0; i<size; i++){
		for (usint j=0; j< size; j++) {
			vektor(i, j).SetValuesToZero();
			for(usint k=0; k<i+j+1; k++)
				vektor(i, j).AddILElementOne();
		}
	}

	std::cout << "vektor: " << vektor << std::endl;
	//std::cout << "vektor col 0: " << vektor.ExtractCol(1) << std::endl;
	//std::cout << "vektor row 2: " << vektor.ExtractRows(2, 2) << std::endl;
	//std::cout << "vektor row 3: " << vektor.ExtractRows(2, 3) << std::endl;
	//std::cout << "vektor col 0: " << vektor.ExtractCol(1) << std::endl;
	std::cout << "vektor cols 1-1: " << vektor.ExtractCols(1, 1) << std::endl;

	return 0;
}

int Simulate(usint argc)
{
	usint n = 4096;
	usint N = n/2;
	usint k = 30;
	usint d = 1; 	// Depth of the circuit
	usint ell = 1 << d; // No of attributes

	BigInteger q = BigInteger::ONE << (k-1);
	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(2)+1.0;
	size_t k_ = (usint) floor(logTwo);
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

	usint m = k_+2;

	ILParams ilParams(n, q, rootOfUnity);
	shared_ptr<ILParams> params = std::make_shared<ILParams>(ilParams);

	auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);
	auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, SIGMA);
	auto uniform_alloc = Poly::MakeDiscreteUniformAllocator(params, COEFFICIENT);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	Matrix<BigInteger> S(BigInteger::Allocator, m, m);

	BigInteger Minus1 = q-BigInteger::ONE;
	for(usint i=0; i<m; i++)
		for(usint j=0; j<m; j++)
			if(bug.GenerateInteger()==BigInteger::ZERO)
				S(i,j) = Minus1;
			else
				S(i,j) = BigInteger::ONE;

	RingMat B(uniform_alloc, d, m);
	RingMat Psi(zero_alloc, m, m);

	std::vector<Poly> R2Vec(m);
	for(usint i=0; i<d; i++) {
		for(usint j=0; j<m; j++) {
			R2Vec = B(i,j).BaseDecompose(1);
			for(usint kk=0; kk<k; kk++) {
				Psi(kk, j) = R2Vec[kk];
			}
		}
	}

	Psi.SwitchFormat();
	std::cout << Psi(m-3,0) << std::endl;
	//std::cout << R2Vec[20] << std::endl;
	//std::cout << R2Vec[21] << std::endl;

	return 0;
}

int ExpErrors(usint argc) {

	// { 4096, "18014398509506561", "5194839201355896"},

	usint m = 4096;
	BigInteger modulus(BigInteger("18014398509506561"));
	BigInteger rootOfUnity(BigInteger("5194839201355896"));

	ILParams ilParams(m, modulus, rootOfUnity);
	shared_ptr<ILParams> params = std::make_shared<ILParams>(ilParams);

	auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);
	auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, SIGMA);
	auto uniform_alloc = Poly::MakeDiscreteUniformAllocator(params, COEFFICIENT);

	size_t n = params->GetCyclotomicOrder() / 2;
	double val = params->GetModulus().ConvertToDouble();
	double logTwo = log(val - 1.0) / log(2) + 1.0;
	size_t k = (usint)floor(logTwo);

	RingMat e(zero_alloc, 1, k, gaussian_alloc);

	std::cout << "Generated gaussian row vector " << std::endl;

	RingMat u1(zero_alloc, 1, k, uniform_alloc);
	RingMat uMatrix1(zero_alloc, k, k);
	for (size_t i = 0; i < k; i++)
		for (size_t j = 0; j < k; j++)
			uMatrix1(j, i) = u1(0, i).GetDigitAtIndexForBase(j+1,2);

	std::cout << "Generated uMatrix1 " << std::endl;

	RingMat u2(zero_alloc, 1, k, uniform_alloc);
	RingMat uMatrix2(zero_alloc, k, k);
	for (size_t i = 0; i < k; i++)
		for (size_t j = 0; j < k; j++)
			uMatrix2(j, i) = u2(0, i).GetDigitAtIndexForBase(j + 1, 2);

	std::cout << "Generated uMatrix2! " << std::endl;

	// go to evaluation representation
	e.SwitchFormat();
	uMatrix1.SwitchFormat();
	uMatrix2.SwitchFormat();

	std::cout << "Converted all three to evaluation representation " << std::endl;

	RingMat level1 = e*uMatrix1;
	RingMat level2 = level1*uMatrix1;

	Poly level2Single(params,EVALUATION,1);

	for (size_t i = 0; i < k; i++)
		level2Single = level2Single + level1(0, i)*uMatrix1(i, 0);

	std::cout << "Ran the product " << std::endl;

	//go back to coefficient representation
	e.SwitchFormat();
	uMatrix1.SwitchFormat();
	uMatrix2.SwitchFormat();
	level1.SwitchFormat();
	level2.SwitchFormat();
	level2Single.SwitchFormat();

	double meanOfError = 0.0;

	for (size_t i = 0; i < k; i++)
	{
		if (e(0, i).Mean() > meanOfError)
			meanOfError = e(0, i).Mean();
	}

	double meanOfLevel1 = 0.0;

	for (size_t i = 0; i < k; i++)
	{
		if (level1(0, i).Mean() > meanOfLevel1)
			meanOfLevel1 = level1(0, i).Mean();
	}

	std::cout << "Switched back to coefficient representation " << std::endl;

	std::cout << " n = " << n << std::endl;
	std::cout << " k = " << k << std::endl;

	std::cout << " Norm of e = " << e.Norm() << std::endl;

	std::cout << " Max mean of e column = " << meanOfError << std::endl;

	std::cout << " Norm of uMatrix1 = " << uMatrix1.Norm() << std::endl;
	std::cout << " Norm of uMatrix2 = " << uMatrix2.Norm() << std::endl;
	std::cout << " Norm of level1 = " << level1.Norm() << std::endl;

	std::cout << " Max mean of level1 column = " << meanOfLevel1 << std::endl;

	std::cout << " Norm of level2 = " << level2.Norm() << std::endl;
	std::cout << " Norm of level2Single = " << level2Single.Norm() << std::endl;

	//system("PAUSE");

	return 1;

}
#endif
