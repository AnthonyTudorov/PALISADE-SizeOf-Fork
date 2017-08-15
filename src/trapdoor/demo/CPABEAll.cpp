#include "abe/kp_abe.h"
#include "abe/cp_abe.h"
#include "abe/ibe.h"
#include <iostream>
#include <fstream>

#include "utils/debug.h"
//#include <valgrind/callgrind.h>

#include <omp.h> //open MP header

using namespace lbcrypto;

int TestKeyGenCP(const shared_ptr<ILParams> ilParams, usint m, usint ell, const usint s[], const RingMat &a, const RingMat &pubElemBPos, const RingMat &pubElemBNeg, const Poly &pubElemU, RingMat &sk);
int CPABE_Test(int iter, int32_t base, usint ringDimension, usint k, usint ell, /*BigInteger q, BigInteger rootOfUnity,*/ bool offline);

struct Params_Set {
	usint base;			// Base
	usint q;	        // modulus bit size
	usint ringDimension;	
	string modulus;
	string rootOfUnity;
};

int main()
{

	std::cout << "-------Start demo for CP-ABE-------" << std::endl;

	Params_Set const cpabe_params[] = {
		{ 2, 32, 1024, "1073750017", "87849761"},
		{ 4, 32, 1024, "1073750017", "143852881"},
		{ 8, 32, 1024, "1073750017", "572531104"},
		{ 16, 33, 1024, "2147577857", "1900992427"},
		{ 32, 34, 1024, "4295688193", "2328426645"},
		{ 64, 35, 1024, "8590151681", "2049477248"},
		{ 128, 36, 1024, "8590151681", "7863638704"},
		{ 256, 37, 1024, "34359771137", "23564286758"},
		{ 512, 37, 1024, "34359771137", "23564286758"},
		{ 1024, 37, 1024, "68719484929", "25395964250"}
	};	

	usint ell[] = { 6, 8, 16, 20, 32 };  
	for(usint i = 0; i < 10;i++){
		BigInteger modulus(cpabe_params[i].modulus);
		BigInteger rootOfUnity(cpabe_params[i].rootOfUnity);
		for(usint j = 0; j < 5; j++){
			CPABE_Test(100, cpabe_params[i].base, cpabe_params[i].ringDimension, cpabe_params[i].q, ell[j],/* modulus, rootOfUnity,*/ true);
		}
	}	
	std::cout << "-------End demo for CP-ABE-------" << std::endl << std::endl;

	return 0;
}



int CPABE_Test(int iter, int32_t base, usint ringDimension, usint k, usint ell,/* BigInteger q, BigInteger rootOfUnity,*/ bool offline)
{
//	k = 36;
	usint n = ringDimension*2;

	BigInteger q = BigInteger::ONE << (k-1);
	q = lbcrypto::FirstPrime<BigInteger>(k,n);
	BigInteger rootOfUnity = (RootOfUnity(n, q));

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

		if(offline){
	//		CALLGRIND_START_INSTRUMENTATION;
	//		CALLGRIND_TOGGLE_COLLECT;
			perturbationVector = pkg.KeyGenOffline( trapdoor.second, dgg);
	//		CALLGRIND_TOGGLE_COLLECT;
	//		CALLGRIND_STOP_INSTRUMENTATION;
		}
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
		sender.Encrypt(ilParams, trapdoor.first, pubElemBPos, pubElemBNeg, u, w, ptext, dgg, dug, &ctW, &ctCPos, &nC, &c1);
		finish = currentDateTime();
		avg_enc += (finish - start);
	//	std::cout << "Encryption time : " << "\t" << (finish - start) << " ms" << std::endl;

		start = currentDateTime();
		receiver.Decrypt(w, s, sk, ctW, ctCPos, nC, c1, &dtext);
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



