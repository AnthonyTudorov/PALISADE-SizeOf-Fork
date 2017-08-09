#include "abe/kp_abe.h"
#include "abe/cp_abe.h"
#include "abe/ibe.h"
#include <iostream>
#include <fstream>

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace lbcrypto;

int IBE_Test(int iter, int32_t base, usint ringDimension, usint k, BigInteger q, BigInteger rootOfUnity, bool offline);
int TestKeyGenCP(const shared_ptr<ILParams> ilParams, usint m, usint ell, const usint s[], const RingMat &a, const RingMat &pubElemBPos, const RingMat &pubElemBNeg, const Poly &pubElemU, RingMat &sk);
int CPABE_Test(int iter, int32_t base, usint ringDimension, usint k, usint ell, BigInteger q, BigInteger rootOfUnity, bool offline);

struct Params_Set {
	usint base;			// Base
	usint q;	        // modulus bit size
	usint ringDimension;	
	string modulus;
	string rootOfUnity;
};

int main()
{

	
/*	std::cout << "-------Start demo for CP-ABE-------" << std::endl;

	Params_Set const cpabe_params[] = {
		{ 2, 31, 1024, "2147577857", "1289872274"}, 
		{ 4, 31, 1024, "2147577857", "663556699"},
		{ 8, 31, 1024, "2147577857", "305569228"},
		{ 16, 34, 2048, "17183748097", "15765111296"},
		{ 32, 35, 2048, "34359754753", "11639358469"},
		{ 64, 37, 2048, "68719484929", "13885715160"},
		{ 128, 39, 2048, "137439072257", "122163940028"},
		{ 256, 40, 2048, "274878136321", "206059740088"},
		{ 512, 41, 2048, "549755904001", "300965887617"},
		{ 1024, 44, 2048, "8796093050881", "3269718423574"}
	};	

	usint ell[] = { 6, 8, 16, 20, 32 }; 
	for(usint i = 7; i < 10;i++){
		BigInteger modulus(cpabe_params[i].modulus);
		BigInteger rootOfUnity(cpabe_params[i].rootOfUnity);
		for(usint j = 0; j < 5; j++){
			CPABE_Test(10000, cpabe_params[i].base, cpabe_params[i].ringDimension, cpabe_params[i].q, ell[j], modulus, rootOfUnity, true);
		}
	}	
	std::cout << "-------End demo for CP-ABE-------" << std::endl << std::endl;
*/
	std::cout << "-------Start demo for IBE-------" << std::endl;
	Params_Set const ibe_params[] = {
		{ 2, 31, 1024, "1073753089", "95035528"}, 
		{ 4, 31, 1024, "1073753089", "133472618"},
		{ 8, 31, 1024, "1073753089", "95035528"},
		{ 16, 31, 1024, "1073750017", "1070003821"},
		{ 32, 32, 1024, "8590058497", "6739203861"},
		{ 64, 33, 1024, "17179898881", "7826325759"}, // 3 digit number
		{ 128, 34, 1024, "8590058497", "6739203861"}, 
		{ 256, 36, 1024, "34359754753", "9616667887"}, // test 8590058497, 4260165125
		{ 512, 35, 1024, "17179898881", "7826325759"},
		{ 1024, 36, 1024, "34359754753", "9616667887"}
	};	

	for(usint i = 0; i < 10; i++){
		IBE_Test(1000, ibe_params[i].base, ibe_params[i].ringDimension, ibe_params[i].q, ibe_params[i].modulus, ibe_params[i].rootOfUnity, true); //iter. ring dimension, k, bool offline
	}	

	std::cout << "-------End demo for IBE-------" << std::endl << std::endl;

/*
	BigInteger q = BigInteger::ONE;
	q = lbcrypto::FirstPrime<BigInteger>(36,1024);
	BigInteger rootOfUnity(RootOfUnity(1024, q));
	std::cout << "q:" << q << std::endl;
	std::cout << "root of unity:" << rootOfUnity << std::endl;*/

	return 0;
}

int IBE_Test(int iter, int32_t base, usint ringDimension, usint k, BigInteger q, BigInteger rootOfUnity, bool offline)
{

	usint n = ringDimension*2;

    q = lbcrypto::FirstPrime<BigInteger>(k,n);
	rootOfUnity  = RootOfUnity(n, q);

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
	long double start, finish, avg_keygen_offline, avg_keygen_online, avg_enc, avg_dec;

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
	avg_keygen_online = avg_keygen_offline = avg_enc = avg_dec = 0.0;

	for(int i=0; i<iter; i++)
	{
	//	std::cout << "Iter no. " << i << std::endl;

		Poly u(dug, ilParams, EVALUATION);
		shared_ptr<RingMat> perturbationVector;
		if(offline){
			start = currentDateTime();
			perturbationVector = pkg.KeyGenOffline(pubElemA.first, u, pubElemA.second, dgg);
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
//		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();


		start = currentDateTime();
		sender.Encrypt(ilParams, pubElemA.first, u, ptext, dgg, dug, bug, &ctC0, &ctC1);
		finish = currentDateTime();
		avg_enc += (finish - start);
	//	std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(ilParams, sk, ctC0, ctC1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);
	//	std::cout << "Decryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
		//	std::cout << "Encryption fails in iter no. " << i << " \n";
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

	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().Destroy();

	return 0;
}

int CPABE_Test(int iter, int32_t base, usint ringDimension, usint k, usint ell, BigInteger q, BigInteger rootOfUnity, bool offline)
{
	
	usint n = ringDimension*2;
	
	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo); /*+ 1;   (+1) is For NAF */
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length in base " << base << ": "<< k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;
	std::cout << "ell: " << ell << std::endl;

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
	long double start, finish, avg_keygen_offline, avg_keygen_online, avg_enc, avg_dec;

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
	avg_keygen_online = avg_keygen_offline = avg_enc = avg_dec = 0.0;
	for(int i=0; i<iter; i++)
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

		shared_ptr<RingMat> perturbationVector;
		start = currentDateTime();
		if(offline)
			perturbationVector = pkg.KeyGenOffline( trapdoor.second, dgg);

		finish = currentDateTime();
		avg_keygen_offline += (finish - start);
		
		start = currentDateTime();		
		if(offline)
			pkg.KeyGenOnline(ilParams, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, trapdoor.second, dgg, perturbationVector, &sk);
		else
			pkg.KeyGen(ilParams, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, trapdoor.second, dgg, &sk);
		
		finish = currentDateTime();
		avg_keygen_online += (finish - start);
//		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;
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
	//	std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(ilParams, w, s, sk, ctW, ctCPos, nC, c1, &dtext);
		finish = currentDateTime();
		avg_dec += (finish - start);
	//	std::cout << "Decryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		ptext.SwitchFormat();
		if(ptext != dtext) {
			failure++;
			std::cout << "Encryption fails in iter no. " << i << " \n";
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

	
	//	std::cout << "Key generation is successful!\n";
	if (!(u == t1))
		std::cout << "Key generation fails!\n";
	return 0;
}



