#include "abe/cp_abe.h"
#include "abe/cp_abe.cpp"


#include "utils/debug.h"
//#include <valgrind/callgrind.h>

using namespace lbcrypto;
template <class Element>
int TestKeyGenCP(const shared_ptr<typename Element::Params> elementParams, usint m, usint ell, const usint s[], const Matrix<Element> &a, const Matrix<Element> &pubElemBPos, const Matrix<Element> &pubElemBNeg, const Element &pubElemU, Matrix<Element> &sk);
template <class Element>
int CPABE_Test(int iter, int32_t base, usint ringDimension, usint k, usint ell, /*BigInteger q, BigInteger rootOfUnity,*/ bool offline);

struct Params_Set {
	usint base;			// Base
	usint l;	        // modulus bit size
	usint q;
	usint ringDimension;

	string modulus;
	string rootOfUnity;
};

int main()
{

	std::cout << "-------Start demo for CP-ABE-------" << std::endl;

	Params_Set const cpabe_params[] = {
		{ 2, 6, 34, 1024},
		{ 2, 8, 34, 1024},
		{ 2, 16, 35, 1024},
		{ 2, 20, 35, 1024},
		{ 2, 32, 35, 1024},
		{ 4, 6, 34, 1024},
		{ 4, 8, 34, 1024},
		{ 4, 16, 35, 1024},
		{ 4, 20, 35, 1024},
		{ 4, 32, 35, 1024},
		{ 8, 6, 34, 1024},
		{ 8, 8, 35, 1024},
		{ 8, 16, 35, 1024},
		{ 8, 20, 35, 1024},
		{ 8, 32, 36, 1024},
		{ 16, 6, 35, 1024},
		{ 16, 8, 35, 1024},
		{ 16, 16, 36, 1024},
		{ 16, 20, 36, 1024},
		{ 16, 32, 36, 1024},
		{ 32, 6, 36, 1024},
		{ 32, 8, 36, 1024},
		{ 32, 16, 37, 1024},
		{ 32, 20, 37, 1024},
		{ 32, 32, 37, 1024},
		{ 64, 6, 37, 1024},
		{ 64, 8, 37, 1024},
		{ 64, 16, 37, 1024},
		{ 64, 20, 38, 1024},
		{ 64, 32, 38, 1024},
		{ 128, 6, 38, 1024},
		{ 128, 8, 38, 1024},
		{ 128, 16, 38, 1024},
		{ 128, 20, 38, 1024},
		{ 128, 32, 39, 1024},
		{ 256, 6, 38, 1024},
		{ 256, 8, 39, 1024},
		{ 256, 16, 39, 1024},
		{ 256, 20, 39, 1024},
		{ 256, 32, 40, 1024},
		{ 512, 6,  39, 1024},
		{ 512, 8,  40, 1024},
		{ 512, 16,  40, 1024},
		{ 512, 20,  40, 1024},
		{ 512, 32,  41, 1024},
		{ 1024, 6, 40, 1024},
		{ 1024, 8, 40, 1024},
		{ 1024, 16, 41, 1024},
		{ 1024, 20, 41, 1024},
		{ 1024, 32, 42, 1024}
	};	

	for(usint i = 0; i < sizeof(cpabe_params)/sizeof(cpabe_params[0]);i++){
		BigInteger modulus(cpabe_params[i].modulus);
		BigInteger rootOfUnity(cpabe_params[i].rootOfUnity);
			CPABE_Test<NativePoly>(3, cpabe_params[i].base, cpabe_params[i].ringDimension, cpabe_params[i].q, cpabe_params[i].l,/* modulus, rootOfUnity,*/ true);
	}	
	std::cout << "-------End demo for CP-ABE-------" << std::endl << std::endl;

	return 0;
}


template <class Element>
int CPABE_Test(int iter, int32_t base, usint ringDimension, usint k, usint ell,/* BigInteger q, BigInteger rootOfUnity,*/ bool offline)
{
//	k = 36;
	usint n = ringDimension*2;
	typename Element::Integer q = typename Element::Integer(1) << (k-1);
	q = lbcrypto::FirstPrime<typename Element::Integer>(k,n);
	typename Element::Integer rootOfUnity = (RootOfUnity(n, q));

	double val = q.ConvertToDouble();
	double logTwo = log(val-1.0)/log(base)+1.0;
	size_t k_ = (usint) floor(logTwo); /*+ 1;   (+1) is For NAF */
	std::cout<< "k: "<< k <<std::endl;
	std::cout << "q: " << q << std::endl;
	std::cout << "modulus length in base " << base << ": "<< k_ << std::endl;
	std::cout << "root of unity: " << rootOfUnity << std::endl;
	std::cout << "Standard deviation: " << SIGMA << std::endl;
	std::cout << "ell: " << ell << std::endl;

	usint m = k_+2;

	shared_ptr<typename Element::Params> elementParams(new typename Element::Params(n, q, rootOfUnity));

	auto zero_alloc = Element::Allocator(elementParams, COEFFICIENT);

//	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	typename Element::DggType dgg = typename Element::DggType(SIGMA);
	typename Element::DugType dug = typename Element::DugType();
	dug.SetModulus(q);
//	BinaryUniformGenerator bug = BinaryUniformGenerator();
	typename Element::BugType bug = typename Element::BugType();
	// Precompuations for FTT
	ChineseRemainderTransformFTT<typename Element::Vector>::PreCompute(rootOfUnity, n, q);

	Matrix<Element> pubElemBPos(zero_alloc, ell, m);
	Matrix<Element> pubElemBNeg(zero_alloc, ell, m);
	Element u(pubElemBPos(0,0));

	// for timing
	long double start, finish, avg_keygen_offline, avg_keygen_online, avg_enc, avg_dec;

	CPABE<Element> pkg, sender, receiver;

	start = currentDateTime();
//	auto trapdoor = pkg.Setup(ilParams, base, ell, dug, &u, &pubElemBPos, &pubElemBNeg);
	std::pair<Matrix<Element>, RLWETrapdoorPair<Element>> trapdoor  = pkg.Setup(elementParams, base, ell, dug, &u, &pubElemBPos, &pubElemBNeg);
	finish = currentDateTime();
	std::cout << "Setup time : " << "\t" << (finish - start) << " ms" << std::endl;

	sender.Setup(elementParams, base, ell);
	receiver.Setup(elementParams, base, ell);

	// User attributes (randomly generated binary values)
	usint *s = new usint[ell];

	// Access structure
	int *w  = new int[ell];

	// Secret key for the output of the circuit
	Matrix<Element> sk(zero_alloc, m, ell+1);

	// plain text in $R_2$
	Element ptext(elementParams, COEFFICIENT, true);
	// text after the decryption
	Element dtext(elementParams, EVALUATION, true);

	Element c1(dug, elementParams, EVALUATION);

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

		shared_ptr<Matrix<Element>> perturbationVector;
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
			pkg.KeyGenOnline(elementParams, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, trapdoor.second, dgg, perturbationVector, &sk);
		else
			pkg.KeyGen(elementParams, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, trapdoor.second, dgg, &sk);
		
		finish = currentDateTime();
		avg_keygen_online += (finish - start);
//		std::cout << "Key generation time : " << "\t" << (finish - start) << " ms" << std::endl;
		TestKeyGenCP(elementParams, m, ell, s, trapdoor.first, pubElemBPos, pubElemBNeg, u, sk);


		Matrix<Element> ctW(Element::Allocator(elementParams, EVALUATION), lenW+1, m);
		Matrix<Element> ctCPos(Element::Allocator(elementParams, EVALUATION), ell-lenW, m);
		Matrix<Element> nC(Element::Allocator(elementParams, EVALUATION), ell-lenW, m);

		// Encrypt a uniformly randomly selected message ptext (in ptext in $R_2$)
		ptext.SetValues(bug.GenerateVector(ringDimension, q), COEFFICIENT);
		ptext.SwitchFormat();

		start = currentDateTime();
		sender.Encrypt(elementParams, trapdoor.first, pubElemBPos, pubElemBNeg, u, w, ptext, dgg, dug, &ctW, &ctCPos, &nC, &c1);
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

	return 0;
}

template <class Element>
int TestKeyGenCP(
	const shared_ptr<typename Element::Params> ilParams,
	const usint m,
	const usint ell,
	const usint s[],
	const Matrix<Element> &pubTA,
	const Matrix<Element> &publicElemBPos,
	const Matrix<Element> &publicElemBNeg,
	const Element &u,
	Matrix<Element> &sk
)
{
	Element t1(ilParams, EVALUATION, true);
	Element t2(ilParams, EVALUATION, true);

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
