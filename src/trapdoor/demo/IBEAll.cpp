#include "abe/ibe.h"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

int IBE_Test(int iter, int32_t base, usint ringDimension, usint k/*, BigInteger q, BigInteger rootOfUnity*/, bool offline);

struct Params_Set {
	usint base;			// Base
	usint q;	        // modulus bit size
	usint ringDimension;	
	string modulus;
	string rootOfUnity;
};

int main()
{

	std::cout << "-------Start demo for IBE-------" << std::endl;
	Params_Set const ibe_params[] = {
		{ 2, 32, 1024},
		{ 4, 32, 1024},
		{ 8, 32, 1024},
		{ 16, 33, 1024},
		{ 32, 34, 1024},
		{ 64, 35, 1024},
		{ 128, 36, 1024},
		{ 256, 37, 1024},
		{ 512, 37, 1024},
		{ 1024, 37, 1024}
	};	

	for(usint i = 0; i < 10; i++){
		BigInteger modulus(ibe_params[i].modulus);
		BigInteger rootOfUnity(ibe_params[i].rootOfUnity);
		IBE_Test(100, ibe_params[i].base, ibe_params[i].ringDimension, ibe_params[i].q, /*modulus, rootOfUnity,*/ true); //iter. ring dimension, k, bool offline
	}	

	std::cout << "-------End demo for IBE-------" << std::endl << std::endl; 

	return 0;
}

int IBE_Test(int iter, int32_t base, usint ringDimension, usint k/*, BigInteger q, BigInteger rootOfUnity*/, bool offline)

{

	usint n = ringDimension*2;

	BigInteger q = 1 << (k-1);
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

	auto zero_alloc = Poly::Allocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::PreCompute(rootOfUnity, n, q);

	// for timing
	long double start, finish, avg_keygen_offline, avg_keygen_online, avg_enc, avg_dec;

	IBE pkg, sender, receiver;

	start = currentDateTime();
	auto pubElemA = pkg.SetupPKG(ilParams, base);
	finish = currentDateTime();
	std::cout << "Setup time : " << "\t" << (finish - start) << " ms" << std::endl;
	sender.SetupNonPKG(ilParams, base);
	receiver.SetupNonPKG(ilParams, base);
	// Secret key for the output of the circuit
	RingMat sk(zero_alloc, m, 1);
	// plain text in $R_2$
	Poly ptext(ilParams, COEFFICIENT, true);
	// text after the decryption
	Poly dtext(ilParams, EVALUATION, true);
	// ciphertext first and second parts
	RingMat ctC0(Poly::Allocator(ilParams, EVALUATION), 1, m);
	Poly ctC1(dug, ilParams, EVALUATION);
	int failure = 0;
	avg_keygen_online = avg_keygen_offline = avg_enc = avg_dec = 0.0;

	for(int i=0; i<iter; i++)
	{

		Poly u(dug, ilParams, EVALUATION);
		shared_ptr<RingMat> perturbationVector;
		if(offline){
			start = currentDateTime();
			perturbationVector = pkg.KeyGenOffline(pubElemA.second, dgg);
			finish = currentDateTime();
			avg_keygen_offline += (finish - start);
		}

		start = currentDateTime();
		
		if(!offline){
			pkg.KeyGen(pubElemA.first, u, pubElemA.second, dgg, &sk);}
		else{
			pkg.KeyGenOnline(pubElemA.first, u, pubElemA.second, dgg, perturbationVector, &sk);
			
		}
		
		finish = currentDateTime();
		avg_keygen_online += (finish - start);

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();


		start = currentDateTime();
		sender.Encrypt(ilParams, pubElemA.first, u, ptext, dug, &ctC0, &ctC1);
		finish = currentDateTime();
		avg_enc += (finish - start);

		start = currentDateTime();
		receiver.Decrypt(sk, ctC0, ctC1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " Stopping here.\n";
			break;
		}
	}
	if(failure == 0) {
		std::cout << "Encryption/Decryption is successful after " << iter << " iterations!\n";
		std::cout << "Average key generation time online: " << "\t" << (avg_keygen_online)/iter << " ms" << std::endl;
		std::cout << "Average key generation time offline: " << "\t" << (avg_keygen_offline)/iter << " ms" << std::endl;
		std::cout << "Average key generation time total: " << "\t" << (avg_keygen_offline + avg_keygen_online)/iter << " ms" << std::endl;
		std::cout << "Average encryption time : " << "\t" << (avg_enc)/iter << " ms" << std::endl;
		std::cout << "Average decryption time : " << "\t" << (avg_dec)/iter << " ms" << std::endl;
		std::cout << "----------------------------------------------------------------" << std::endl;
	}

	return 0;
}



