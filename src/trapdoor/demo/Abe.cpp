#include "abe/kp_abe.h"
#include "abe/cp_abe.h"
#include "abe/ibe.h"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

int IBE_Test(int iter, int32_t base, usint ringDimension, usint k, bool offline);
int TestKeyGenCP(const shared_ptr<ILParams> ilParams, usint m, usint ell, const usint s[], const RingMat &a, const RingMat &pubElemBPos, const RingMat &pubElemBNeg, const Poly &pubElemU, RingMat &sk);
int CPABE_Test(usint iter);

int main()
{

	
/*	std::cout << "-------Start demo for CP-ABE-------" << std::endl;
	CPABE_Test(1);
	std::cout << "-------End demo for CP-ABE-------" << std::endl << std::endl;*/

	std::cout << "-------Start demo for IBE-------" << std::endl;
	IBE_Test(10000, 1024, 1024, 49, true); //iter. ring dimension, k, bool offline
	std::cout << "-------End demo for IBE-------" << std::endl << std::endl;

	return 0;
}

int IBE_Test(int iter, int32_t base, usint ringDimension, usint k, bool offline)
{
	usint n = ringDimension*2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo); /*+ 1;  (+1) is For NAF */
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

	// for timing
	long double start, finish, avg_keygen, avg_enc, avg_dec;

	IBE pkg, sender, receiver;

	start = currentDateTime();
	auto pubElemA = pkg.Setup(ilParams, base, dug);
	finish = currentDateTime();
	std::cout << "Setup time : " << "\t" << (finish - start) << " ms" << std::endl;

	sender.Setup(ilParams, base);
	receiver.Setup(ilParams, base);

	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, m, 1);

	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);
	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);

	// ciphertext first and second parts
	RingMat ctC0(Poly::MakeAllocator(ilParams, EVALUATION), 1, m);
	Poly ctC1(dug, ilParams, EVALUATION);

	int failure = 0;
	avg_keygen = avg_enc = avg_dec = 0.0;

	for(int i=0; i<iter; i++)
	{
		std::cout << "Iter no. " << i << std::endl;

		Poly u(dug, ilParams, EVALUATION);

		shared_ptr<RingMat> perturbationVector;
		
		if(offline)
			perturbationVector = pkg.KeyGenOffline(pubElemA.first, u, pubElemA.second, dgg);
		start = currentDateTime();
		
		if(!offline)
			pkg.KeyGen(pubElemA.first, u, pubElemA.second, dgg, &sk);
		else
			pkg.KeyGenOnline(pubElemA.first, u, pubElemA.second, dgg, perturbationVector, &sk);
		
		finish = currentDateTime();
		avg_keygen += (finish - start);
		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();


		start = currentDateTime();
		sender.Encrypt(ilParams, pubElemA.first, u, ptext, dgg, dug, bug, &ctC0, &ctC1);
		finish = currentDateTime();
		avg_enc += (finish - start);
		std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(ilParams, sk, ctC0, ctC1, &dtext);
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
		std::cout << "Encryption/Decryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

	return 0;
}

int CPABE_Test(usint iter)
{
	usint ringDimension = 1024;
	usint n = ringDimension*2;
	usint k = 34;
	int32_t base = 4;
	usint ell = 32;

	BigInteger q = BigInteger::ONE << (k-1);
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
	auto trapdoor = pkg.Setup(ilParams, base, ell, dug, &u, &pubElemBPos, &pubElemBNeg);
	finish = currentDateTime();
	std::cout << "Setup time : " << "\t" << (finish - start) << " ms" << std::endl;

	sender.Setup(ilParams, base, ell);
	receiver.Setup(ilParams, base, ell);

	// User attributes (randomly generated binary values)
	usint *s = new usint[ell];

	// Access structure
	int *w  = new int[ell];

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

		start = currentDateTime();
		pkg.KeyGen(ilParams, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, trapdoor.second, dgg, &sk);
		finish = currentDateTime();
		avg_keygen += (finish - start);
		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;
		TestKeyGenCP(ilParams, m, ell, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, sk);


		RingMat ctW(Poly::MakeAllocator(ilParams, EVALUATION), lenW+1, m);
		RingMat ctCPos(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);
		RingMat nC(Poly::MakeAllocator(ilParams, EVALUATION), ell-lenW, m);

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();

		start = currentDateTime();
		sender.Encrypt(ilParams, trapdoor.first, pubElemBPos, pubElemBNeg, u, w, ptext, dgg, dug, bug, &ctW, &ctCPos, &nC, &c1);
		finish = currentDateTime();
		avg_enc += (finish - start);
		std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(ilParams, w, s, sk, ctW, ctCPos, nC, c1, &dtext);
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
		std::cout << "Encryption/Decryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time : " << "\t" << (avg_keygen)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
	}

	delete[] w;
	delete[] s;

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();
	return 0;
}

int TestKeyGenCP(
	const shared_ptr<ILParams> ilParams,
	const usint m,
	const usint ell,
	const usint s[],
	const RingMat &pubTA,
	const RingMat &publicElemBPos,
	const RingMat &publicElemBNeg,
	const Poly &u,
	RingMat &sk
)
{
	Poly t1(ilParams, EVALUATION, true);
	Poly t2(ilParams, EVALUATION, true);

	for(usint i=0; i<ell; i++) {
		if(s[i]==1) {
			t2 = publicElemBPos(i, 0)*sk(0, i+1);
			for(usint j=1; j<m; j++)
				t2 += publicElemBPos(i, j)*sk(j, i+1);
		}
		else {
			t2 = publicElemBNeg(i, 0)*sk(0, i+1);
			for(usint j=1; j<m; j++)
				t2 += publicElemBNeg(i, j)*sk(j, i+1);
		}
		t1 += t2;
	}

	t2 = pubTA(0, 0)*sk(0, 0);
	for(usint j=1; j<m; j++)
		t2 += pubTA(0, j)*sk(j, 0);

	t1 += t2;

	if (u == t1)
		std::cout << "Key generation is successful!\n";
	else
		std::cout << "Key generation fails!\n";
	return 0;
}



