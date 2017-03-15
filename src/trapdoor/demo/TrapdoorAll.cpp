#include "signature/lwesign.h"
#include "signature/lwesign.cpp"
#include "encoding/byteplaintextencoding.h"

#include <omp.h> //open MP header

//#define ONLINE_TIMING 1
//#define OFFLINE_TIMING 1
using namespace lbcrypto;

struct SecureParams {
	usint m;			///< The ring parameter.
	string modulus;	///< The modulus
	string rootOfUnity;	///< The rootOfUnity
};

void MultiThreadedRun(int index);

int main() {

	for (usint i = 3; i < 4; i++) {
		MultiThreadedRun(i);
	}

	ChineseRemainderTransformFTT<BigBinaryInteger, BigBinaryVector>::GetInstance().Destroy();
	NumberTheoreticTransform<BigBinaryInteger, BigBinaryVector>::GetInstance().Destroy();
	DiscreteFourierTransform::GetInstance().Destroy();

	return 0;
}

void MultiThreadedRun(int index) {

	int nthreads, tid;

	// Fork a team of threads giving them their own copies of variables
	//so we can see how many threads we have to work with
#pragma omp parallel private(nthreads, tid)
	{

		/* Obtain thread number */
		tid = omp_get_thread_num();

		/* Only master thread does this */
		if (tid == 0)
		{
			nthreads = omp_get_num_threads();
			std::cout << "Number of threads = " << nthreads << std::endl;
		}
	}

	SecureParams const SECURE_PARAMS[] = {
		{ 1024, "8399873", "824894"}, 
		{ 2048, "67127297", "19715182"},
		{ 4096, "18014398509506561", "5194839201355896"},
		{ 8192, "162259276829213363391578010402817", "66396805305014513556659676765098"},
		{ 16384, "13164036458569648337239753460458804039861886925068638906789969921", "146488057101847996735943188821846167958454591207690706445995891"} 
	};

	size_t counter = 50;
	double start, finish;
	DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector> dgg(SIGMA);

	usint sm = SECURE_PARAMS[index].m;
	BigBinaryInteger smodulus(SECURE_PARAMS[index].modulus);
	BigBinaryInteger srootOfUnity(SECURE_PARAMS[index].rootOfUnity);

	ILParams ilParams(sm, smodulus, srootOfUnity);
	shared_ptr<ILParams> silParams = std::make_shared<ILParams>(ilParams);

	ilParams.SetCyclotomicOrder(sm);
	ilParams.SetRootOfUnity(srootOfUnity);
	ilParams.SetModulus(smodulus);
	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	DiscreteFourierTransform::GetInstance().PreComputeTable(sm);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

	silParams = std::make_shared<ILParams>(ilParams);
	LPSignatureParameters signParams(silParams, dgg);
	signParams.SetElemParams(silParams);
	std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;

	//std::cout << "std = " << signParams.GetDiscreteGaussianGenerator().GetStd() << std::endl;

	LPSignKeyGPVGM<ILVector2n> s_k_gm(signParams);
	LPVerificationKeyGPVGM<ILVector2n> v_k_gm(signParams);
	LPSignatureSchemeGPVGM<ILVector2n> scheme_gm;

	vector<Signature<Matrix<ILVector2n>>> signature(counter);

	scheme_gm.KeyGen(&s_k_gm, &v_k_gm);

	start = currentDateTime();

	for (usint i = 0; i < 10; i++) {

		scheme_gm.KeyGen(&s_k_gm, &v_k_gm);

	}
		
	finish = currentDateTime();

	std::cout << "Key generation - New : " << "\t" << (finish - start)/10 << " ms" << std::endl;

	double signTime = 0;
	double verifyTime = 0;
	size_t verifyCounter = 0;
	bool verifyBool = false;

	std::vector<BytePlaintextEncoding> text{
		"1 Let's spice things up",
		"2 Let's spice things up",
		"3 Let's spice things up",
		"4 Let's spice things up",
		"5 Let's spice things up",
		"6 Let's spice things up",
		"7 Let's spice things up",
		"8 Let's spice things up",
		"9 Let's spice things up",
		"10 Let's spice things up",
	};

	Signature<Matrix<ILVector2n>> precompSignature;

	scheme_gm.Sign(s_k_gm, text[5], &precompSignature);

	start = currentDateTime();

	for (usint i = 0; i < counter; i++) {

		scheme_gm.Sign(s_k_gm, text[i % 10], &(signature[i]));

	}
		
	finish = currentDateTime();

	signTime = finish - start;

	std::cout << "Signing - New : " << "\t" << signTime / counter << " ms" << std::endl;

	start = currentDateTime();

	for (usint i = 0; i < counter; i++) {

		verifyBool = scheme_gm.Verify(v_k_gm, signature[i], text[i % 10]);

		if (verifyBool)
			verifyCounter++;

	}

	finish = currentDateTime();

	verifyTime = finish - start;


	std::cout << "Verifying - New : " << "\t" << verifyTime / counter << " ms" << std::endl;
	std::cout << "Verification counter : " << "\t" << verifyCounter << "\n" << std::endl;

	std::cout << "Execution completed" << std::endl;


}

