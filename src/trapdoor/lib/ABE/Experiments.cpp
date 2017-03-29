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
#include "obfuscation/lweconjunctionobfuscatev3.h"
#include "obfuscation/lweconjunctionobfuscatev3.cpp"

#include "utils/debug.h"

#include <omp.h> //open MP header

//using namespace std;
using namespace lbcrypto;

int Simulate(int argc) {

	usint n = 4096;
	usint N = n/2;
	usint k = 30;
	usint d = 1; 	// Depth of the circuit
	usint ell = 1 << d; // No of attributes

	BigBinaryInteger q = BigBinaryInteger::ONE << (k-1);
	lbcrypto::NextQ(q, BigBinaryInteger::TWO, n, BigBinaryInteger("4"), BigBinaryInteger("4"));
	BigBinaryInteger rootOfUnity(RootOfUnity(n, q));

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

	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
	auto gaussian_alloc = ILVector2n::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, SIGMA);
	auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, COEFFICIENT);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(rootOfUnity, n, q);
	// ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, n, q);

	Matrix<BigBinaryInteger> S(BigBinaryInteger::Allocator, m, m);

	BigBinaryInteger Minus1 = q-BigBinaryInteger::ONE;
	for(int i=0; i<m; i++)
		for(int j=0; j<m; j++)
			if(bug.GenerateInteger()==BigBinaryInteger::ZERO)
				S(i,j) = Minus1;
			else
				S(i,j) = BigBinaryInteger::ONE;

	RingMat B(uniform_alloc, d, m);
	RingMat Psi(zero_alloc, m, m);

	std::vector<ILVector2n> R2Vec(m);
	for(int i=0; i<d; i++) {
		for(int j=0; j<m; j++) {
			R2Vec = B(i,j).BaseDecompose(1);
			for(int kk=0; kk<k; kk++) {
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


int ExpErrors(int argc) {

	// { 4096, "18014398509506561", "5194839201355896"},

	usint m = 4096;
	BigBinaryInteger modulus(BigBinaryInteger("18014398509506561"));
	BigBinaryInteger rootOfUnity(BigBinaryInteger("5194839201355896"));

	ILParams ilParams(m, modulus, rootOfUnity);
	shared_ptr<ILParams> params = std::make_shared<ILParams>(ilParams);

	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
	auto gaussian_alloc = ILVector2n::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, SIGMA);
	auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, COEFFICIENT);

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

	ILVector2n level2Single(params,EVALUATION,1);

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
