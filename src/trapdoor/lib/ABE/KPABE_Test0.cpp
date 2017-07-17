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
#include "KP_ABE.h"

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;
void CheckSecretKey(usint m, RingMat &A, RingMat &Bf, RingMat &SecKey, Poly &beta);
usint EvalNANDTree(usint *x, usint ell);

int KPABE_BenchmarkCircuitTest(usint iter, int32_t base)
{
	usint N = 2048;   // ring dimension
	usint n = N*2;   // cyclotomic order
	usint k = 51;
	usint ell = 8; // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
//	lbcrypto::NextPrime(q,n);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
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

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA); // A.first is the public element

	Poly beta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat Cin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE pkg, sender, receiver;

	pkg.Setup(ilParams, base, ell, dug, &publicElementB);
	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell+1];
	x[0] = 1;
	usint found  = 0;
	while(found == 0) {
		for(usint i=1; i<ell+1; i++)
			x[i] = rand()&0x1;
		if(EvalNANDTree(&x[1], ell) == 0)
			found = 1;
	}

	for(usint i =0; i < ell+1;i++){
		std::cout << x[i] << std::endl;
	}

	usint y;

	// plaintext
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat Bf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  //evaluated Bs
	RingMat Cf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);  // evaluated Cs
	RingMat CA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m); // CA

	// secret key corresponding to the circuit output
	RingMat sKey(zero_alloc, 2, m);

	// decrypted text
	Poly dtext(ilParams, EVALUATION, true);

	int failure = 0;
	double start, finish, avg_keygen, avg_eval, avg_enc, avg_dec;
	avg_keygen=avg_eval=avg_enc=avg_dec=0.0;
	for(usint i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(N, q), COEFFICIENT);
		ptext.SwitchFormat();
		start = currentDateTime();
		sender.Encrypt(ilParams, A.first, publicElementB, beta, x, ptext, dgg, dug, bug, &Cin, &c1); // Cin and c1 are the ciphertext
		finish = currentDateTime();
		avg_enc += (finish - start);

		CA  = Cin.ExtractRow(0);  // CA is A^T * s + e 0,A

		start = currentDateTime();
	//	RECEIVER.EvalPK(ilParams, B, &Bf);
		receiver.EvalCT(ilParams, publicElementB, x, Cin.ExtractRows(1, ell+1), &y, &Cf);

		finish = currentDateTime();
		avg_eval += (finish - start);

		start = currentDateTime();
		pkg.EvalPK(ilParams, publicElementB, &Bf);
		pkg.KeyGen(ilParams, A.first, Bf, beta, A.second, dgg, &sKey);
		finish = currentDateTime();
		avg_keygen += (finish - start);
		CheckSecretKey(m, A.first, Bf, sKey, beta);

		start = currentDateTime();
		receiver.Decrypt(ilParams, sKey, CA, Cf, c1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);

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
		std::cout << "Average evaluation time : " << "\t" << (avg_eval)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	delete x;

	return 0;
}


/*
 * The access policy is x1*x2+x3*x4 = (1-x1x2)*(1-x3x4)
 */
int KPABE_APolicyCircuitTest(usint iter)
{
	usint N = 2048;   // ring dimension
	usint n = N*2;   // cyclotomic order
	usint k = 42;
	usint ell = 4; // No of attributes for NAND gate
	int32_t base = 2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo)+1; /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
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

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);

	Poly beta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat Cin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE PKG, SENDER, RECEIVER;

	PKG.Setup(ilParams, base, ell, dug, &publicElementB);
	SENDER.Setup(ilParams, base, ell);
	RECEIVER.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell+1];
	for(usint i=0; i<ell+1; i++)
		x[i] = 1;
	//x[1] = x[3] = 0;   // Must fail when uncommented (a policy cicuti always output 0) 
	

	// plaintext
	Poly ptext(ilParams, COEFFICIENT, true);

	// outputs of the input gates
	RingMat tB(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat tC(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat wB(Poly::MakeAllocator(ilParams, EVALUATION), 2, m);
	RingMat wC(Poly::MakeAllocator(ilParams, EVALUATION), 2, m);
	usint wx[2];

	// circuit outputs
	RingMat Bf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat Cf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat CA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	usint y;  // output of the circuit; for the policy (i.e., x1=x2=1 OR x3=x4=1) it should be 0


	// secret key corresponding to the circuit output
	RingMat sKey(zero_alloc, 2, m);

	// decrypted text
	Poly dtext(ilParams, EVALUATION, true);

	int failure = 0;
	for(usint i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(N, q), COEFFICIENT);
		ptext.SwitchFormat();
		SENDER.Encrypt(ilParams, A.first, publicElementB, beta, x, ptext, dgg, dug, bug, &Cin, &c1);

		CA  = Cin.ExtractRow(0);
		auto B0 = publicElementB.ExtractRow(0);
		auto C0 = Cin.ExtractRow(1);

		RECEIVER.NANDGateEval(ilParams, B0, C0, &x[1], publicElementB.ExtractRows(1,2), Cin.ExtractRows(2,3), &wx[0], &tB, &tC);

		for(usint i=0; i<m; i++) {
			wB(0, i) = tB(0, i);
			wC(0, i) = tC(0, i);
		}

		RECEIVER.NANDGateEval(ilParams, B0, C0, &x[3], publicElementB.ExtractRows(3,4), Cin.ExtractRows(4,5), &wx[1], &tB, &tC);

		for(usint i=0; i<m; i++) {
			wB(1, i) = tB(0, i);
			wC(1, i) = tC(0, i);
		}

		RECEIVER.ANDGateEval(ilParams, wx, wB, wC, &y, &Bf, &Cf);

		PKG.KeyGen(ilParams, A.first, Bf, beta, A.second, dgg, &sKey);
		//CheckSecretKey(m, A.first, Bf, sKey, beta);

		RECEIVER.Decrypt(ilParams, sKey, CA, Cf, c1, &dtext);

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}

	}
	if(failure == 0)
		std::cout << "Encryption is successful after " << iter << " iterations!\n";

	delete x;

	return 0;
}

int KPABE_NANDGateTest(usint iter, int32_t base)
{
	usint N = 1024;
	usint n = N*2;
	usint k = 36;
	usint ell = 2; // No of attributes for NAND gate

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length in base " << base << ": " << k_ << std::endl;
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

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);


	Poly beta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat Cin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE PKG, SENDER, RECEIVER;

	PKG.Setup(ilParams, base, ell, dug, &publicElementB);
	SENDER.Setup(ilParams, base, ell);
	RECEIVER.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell];
	x[0] = x[1] = x[2] = 1;
	usint y;
	//x[1] = 0;   // This should fail the NAND gate evaluation as now the output is 1 (should be 0 for a policy circuit)

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat Bf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat Cf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat CA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);

	// Secret key for the output of the circuit
	RingMat sKey(zero_alloc, 2, m);

	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	int failure = 0;
	double start, finish, avg_keygen, avg_eval, avg_enc, avg_dec;
	avg_keygen=avg_eval=avg_enc=avg_dec=0.0;
	for(usint i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(N, q), COEFFICIENT);
		ptext.SwitchFormat();
		start = currentDateTime();
		SENDER.Encrypt(ilParams, A.first, publicElementB, beta, x, ptext, dgg, dug, bug, &Cin, &c1);
		finish = currentDateTime();
		avg_enc += (finish - start);

		CA = Cin.ExtractRow(0);

		/*RECEIVER.NANDGateEval(ilParams,
				B.ExtractRow(0), Cin.ExtractRow(1),
				&x[1], B.ExtractRows(1,2), Cin.ExtractRows(2,3), &y, &Bf, &Cf);*/
		start = currentDateTime();
		RECEIVER.KPABE::NANDGateEval(ilParams,
				publicElementB.ExtractRow(0), Cin.ExtractRow(1),
				&x[1], publicElementB.ExtractRows(1,2), Cin.ExtractRows(2,3), &y, &Bf, &Cf);
		finish = currentDateTime();
		avg_eval += (finish - start);
		
		start = currentDateTime();
		PKG.KeyGen(ilParams, A.first, Bf, beta, A.second, dgg, &sKey);
		finish = currentDateTime();
		avg_keygen += (finish - start);
		//CheckSecretKey(m, A.first, Bf, sKey, beta);

		start = currentDateTime();
		RECEIVER.Decrypt(ilParams, sKey, CA, Cf, c1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);

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
		std::cout << "Average evaluation time : " << "\t" << (avg_eval)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	return 0;
}

int KPABE_ANDGateTest(usint iter)
{
	usint N = 1024;
	usint n = N*2;
	usint k = 30;
	usint ell = 2; // No of attributes for NAND gate
	int32_t base = 2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo) + 1;  /* (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length: " << k_ << std::endl;
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

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);

	Poly beta(dug, ilParams, EVALUATION);

	RingMat publicElementB(zero_alloc, ell+1, m);
	RingMat Cin(zero_alloc, ell+2, m);
	Poly c1(dug, ilParams, EVALUATION);

	KPABE PKG, SENDER, RECEIVER;

	PKG.Setup(ilParams, base, ell, dug, &publicElementB);
	SENDER.Setup(ilParams, base, ell);
	RECEIVER.Setup(ilParams, base, ell);

	// Attribute values all are set to 1 for NAND gate evaluation
	usint *x = new usint[ell];
	x[0] = x[1] = x[2] = 0;
	usint y;
	//x[1] = x[2] = 1;   // When uncommented this should fail (a policy circuit always outputs 0

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);

	// circuit outputs
	RingMat Bf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat Cf(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	RingMat CA(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);

	// Secret key for the output of the circuit
	RingMat sKey(zero_alloc, 2, m);

	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	int failure = 0;
	for(usint i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(N, q), COEFFICIENT);
		ptext.SwitchFormat();
		SENDER.Encrypt(ilParams, A.first, publicElementB, beta, x, ptext, dgg, dug, bug, &Cin, &c1);

		CA = Cin.ExtractRow(0);

		RECEIVER.ANDGateEval(ilParams, &x[1], publicElementB.ExtractRows(1,2), Cin.ExtractRows(2,3), &y, &Bf, &Cf);

		PKG.KeyGen(ilParams, A.first, Bf, beta, A.second, dgg, &sKey);

		RECEIVER.Decrypt(ilParams, sKey, CA, Cf, c1, &dtext);

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
			break;
		}

	}
	if(failure == 0)
		std::cout << "Encryption is successful after " << iter << " iterations!\n";

	return 0;
}


void CheckSecretKey(usint m, RingMat &A, RingMat &Bf, RingMat &SecKey, Poly &beta)
{
	Poly t(beta);
	t.SetValuesToZero();
	for (usint i=0; i<m; i++) {
		t += (A(0, i)*SecKey(0, i));
		t += (Bf(0, i)*SecKey(1, i));
	}

	if(t == beta)
		std::cout << "Secret Key Generation is Successful!\n";
	else
		std::cout << "Secret Key Generation Fails!\n";
}


usint EvalNANDTree(usint *x, usint ell)
{
	usint y;

	if(ell == 2) {
		y = 1 - x[0]*x[1];
		return y;
	}
	else {
		ell >>= 1;
		y = 1 - (EvalNANDTree(&x[0], ell)*EvalNANDTree(&x[ell], ell));
	}
	return y;
}

