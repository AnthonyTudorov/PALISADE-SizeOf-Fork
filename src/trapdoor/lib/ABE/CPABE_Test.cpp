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

#include <iostream>
#include <fstream>
#include "CP_ABE.h"

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

int testKeyGen(const shared_ptr<ILParams> ilParams, usint m, usint ell, const usint S[], const RingMat &A, const RingMat &B, const RingMat &nB, const Poly &u, RingMat &sKey);

int CPABE_Test(usint iter)
{
	usint N = 1024;
	usint n = N*2;
	usint k = 34;
	int32_t base = 4;
	usint ell = 32;

	BigInteger q = BigInteger::ONE << (k-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length in base " << base << ": "<< k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;

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

	// for timing
	double start, finish, avg_keygen, avg_enc, avg_dec;

	CPABE pkg, sender, receiver;

	start = currentDateTime();
	auto A = pkg.Setup(ilParams, base, ell, dug, &u, &pubElemBPos, &pubElemBNeg);
	finish = currentDateTime();
	std::cout << "Setup time : " << "\t" << (finish - start) << " ms" << std::endl;

	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// User attributes (randomly generated binary values)
	usint *S = new usint[ell];

	// Access structure
	int *w = new int[ell];

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, m, ell+1);

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);
	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	Poly c1(dug, ilParams, EVALUATION);

	int failure = 0;
	avg_keygen = avg_enc = avg_dec = 0.0;
	for(usint i=0; i<iter; i++)
	{
//		std::cout << "Iter no. " << i << std::endl;

		for(usint j=0; j<ell; j++)
			S[j] = rand()%2;

		for(usint j=0; j<ell; j++)
			w[j] = S[j];

		for(usint j=0; j<ell; j++)
			if(w[j]==1) {
				w[j] = 0;
				break;
			}

		for(usint j=0; j<ell; j++)
			if(S[j]==0) {
				w[j] = -1;
				break;
			}

		usint lenW = 0;
		for(usint j=0; j<ell; j++)
			if(w[j] != 0)
				lenW++;

		start = currentDateTime();
		pkg.KeyGen(ilParams, S, A.first, pubElemBPos, pubElemBNeg, u, A.second, dgg, &sk);
		finish = currentDateTime();
		avg_keygen += (finish - start);
		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;
		testKeyGen(ilParams, m, ell, S, A.first, pubElemBPos, pubElemBNeg, u, sk);


		RingMat ctW(Poly::MakeAllocator(ilParams, EVALUATION), lenW+1, m);
		RingMat ctCPos(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);
		RingMat nC(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(N, q), COEFFICIENT);
		ptext.SwitchFormat();

		start = currentDateTime();
		sender.Encrypt(ilParams, A.first, pubElemBPos, pubElemBNeg, u, w, ptext, dgg, dug, bug, &ctW, &ctCPos, &nC, &c1);
		finish = currentDateTime();
		avg_enc += (finish - start);
		std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(ilParams, w, S, sk, ctW, ctCPos, nC, c1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);
		std::cout << "Decryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}
	}
	if(failure == 0) {
		std::cout << "Encryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	delete w;
	delete S;
	return 0;
}


int testKeyGen(
	const shared_ptr<ILParams> ilParams,
	const usint m,
	const usint ell,
	const usint s[],
	const RingMat &pubTA,
	const RingMat &publicElemBPos,
	const RingMat &publicElemBNeg,
	const Poly &u,
	RingMat &sKey
)
{
	Poly t1(ilParams, EVALUATION, true);
	Poly t2(ilParams, EVALUATION, true);

	for(usint i=0; i<ell; i++) {
		if(s[i]==1) {
			t2 = publicElemBPos(i, 0)*sKey(0, i+1);
			for(usint j=1; j<m; j++)
				t2 += publicElemBPos(i, j)*sKey(j, i+1);
		}
		else {
			t2 = publicElemBNeg(i, 0)*sKey(0, i+1);
			for(usint j=1; j<m; j++)
				t2 += publicElemBNeg(i, j)*sKey(j, i+1);
		}
		t1 += t2;
	}

	t2 = pubTA(0, 0)*sKey(0, 0);
	for(usint j=1; j<m; j++)
		t2 += pubTA(0, j)*sKey(j, 0);

	t1 += t2;

	if (u == t1)
		std::cout << "Key generation is successful!\n";
	else
		std::cout << "Key generation fails!\n";
	return 0;
}

