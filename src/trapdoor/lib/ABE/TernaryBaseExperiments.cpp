#define PROFILE  //define this to enable PROFILELOG and TIC/TOC
// Note must must be before all headers

#include <iostream>
#include <fstream>
#include <iomanip>
//#include "obfuscation/lweconjunctionobfuscatev3.h"
//#include "obfuscation/lweconjunctionobfuscatev3.cpp"
#include "KP_ABE.h"

#include "utils/debug.h"

#include <omp.h> //open MP header

//using namespace std;
using namespace lbcrypto;

int TestTernaryBase_01 (int arg)
{
	usint N = 1024;
	usint n = N*2;
	size_t k_ = 30;
	int32_t base = 16;

	BigInteger q = BigInteger::ONE << (k_-1);
//	lbcrypto::NextQ(q, BigInteger::TWO, n, BigInteger("4"), BigInteger("4"));
	lbcrypto::NextPrime(q,n);
	BigInteger rootOfUnity(RootOfUnity(n, q));

	if(q.GetLengthForBase(2) != k_) {
		std::cout << "Bit size is not supported!" <<std::endl;
		return -1;
	}

	double val = q.ConvertToDouble();
	double logBase = log(val-1.0)/log(base)+1.0;
	size_t k = (usint) floor(logBase) + 1;  /* (+1) is for balanced representation */

	size_t m = k + 2;

	std::cout << "Modulus length in base " << base << ": " << k << std::endl;
	std::cout << "Modulus: " << q << std::endl;
	std::cout << "Ring dimension: " << N << std::endl;

	shared_ptr<ILParams> ilParams(new ILParams(n, q, rootOfUnity));

	auto zero_alloc = Poly::MakeAllocator(ilParams, COEFFICIENT);

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(SIGMA);
	Poly::DugType dug = Poly::DugType();
	dug.SetModulus(q);
	BinaryUniformGenerator bug = BinaryUniformGenerator();

	// Precompuations for FTT
	ChineseRemainderTransformFTT<BigInteger, BigVector>::GetInstance().PreCompute(rootOfUnity, n, q);

	// for timing
	double start, finish;

	start = currentDateTime();

	// Trapdoor Generation
	std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGenwBase(ilParams, base, SIGMA);
	//std::pair<RingMat, RLWETrapdoorPair<Poly>> A = RLWETrapdoorUtility::TrapdoorGen(ilParams, SIGMA);

	finish = currentDateTime();
	std::cout << "Trapdoor Generation : " << "\t" << (finish - start) << " ms" << std::endl;


	Poly perturbedSyndrome(ilParams, COEFFICIENT, true);
	perturbedSyndrome.SetValues(dug.GenerateVector(N), COEFFICIENT);

	//std::cout << "Perturbed syndrome: " << perturbedSyndrome << std::endl;
	//std::cout << "Get length: " << perturbedSyndrome.GetLength() << std::endl;

	Matrix<int32_t> zHatBBI([]() { return make_unique<int32_t>(); }, k, N);

	LatticeGaussSampUtility::GaussSampGq(perturbedSyndrome, SIGMA, k, q, base, dgg, &zHatBBI);

	// Convert zHat from a matrix of BBI to a vector of Poly ring elements
	// zHat is in the coefficient representation
	RingMat zHat = SplitInt32AltIntoPolyElements(zHatBBI, N, ilParams);
	// Now converting it to the evaluation representation before multiplication
	zHat.SwitchFormat();

	RingMat G = RingMat(zero_alloc, 1, k).GadgetVector(base);

	Poly Gz(ilParams, COEFFICIENT, true);
	Gz.SwitchFormat();

	for(usint i=0; i<k; i++) {
		Gz += G(0, i)*zHat(i, 0);
	}
	Gz.SwitchFormat();
	//std::cout << "Gz: " << Gz << std::endl;

	if(perturbedSyndrome == Gz)
		std::cout << "Success!\n";
	else
		std::cout << "Failure!\n";

	/* Trapdoor Part */
	/*****************/
	std::cout << "Full trapdoor Part:\n";

	Poly syndrome(ilParams, COEFFICIENT, true);
	syndrome.SetValues(dug.GenerateVector(N), COEFFICIENT);
	syndrome.SwitchFormat();

	double c = 2 * SIGMA;
	double s = SPECTRAL_BOUND(N, m - 2);
	DiscreteGaussianGenerator dggLargeSigma(sqrt(s * s - c * c));

	RingMat secretKey(Poly::MakeAllocator(ilParams, EVALUATION), m, 1);
	start = currentDateTime();
	secretKey = RLWETrapdoorUtility::GaussSamp(N, k, A.first, A.second, syndrome, base, SIGMA, dgg, dggLargeSigma);
	finish = currentDateTime();
	std::cout << "Preimage Sampling : " << "\t" << (finish - start) << " ms" << std::endl;

	Poly Ax(ilParams, COEFFICIENT, true);
	Ax.SetValuesToZero();
	Ax.SwitchFormat();

	for(usint i=0; i<m; i++) {
		Ax += A.first(0, i)*secretKey(i, 0);
	}

	//std::cout << "Syndrome: " << syndrome << std::endl;
	//std::cout << "Ax: " << Ax << std::endl;

	if(syndrome == Ax)
		std::cout << "Success!\n";
	else
		std::cout << "Failure!\n";

	std::cout << "Ternary: " << ternaryLUT[0][1] << " Size: \t" << ternaryLUT.size() << std::endl;


	return 0;
}
