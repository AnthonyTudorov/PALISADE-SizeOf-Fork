/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 
#include "signature/lwesign.h"
#include "signature/lwesign.cpp"
#include "encoding/encodings.h"

#include <omp.h> //open MP header

//#define ONLINE_TIMING 1
//#define OFFLINE_TIMING 1
using namespace lbcrypto;

struct SecureParams {
	usint m;			///< The ring parameter.
	std::string modulus;	///< The modulus
	std::string rootOfUnity;	///< The rootOfUnity
};

void MultiThreadedRun(int index, usint base);

int main() {

	for (usint i = 0; i < 1; i++) {
		for (usint j = 2; j < 1<<20; j = 2 * j) {
			MultiThreadedRun(i, j);
		}
	}

	DiscreteFourierTransform::Reset();

	return 0;
}

void MultiThreadedRun(int index, usint base) {

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

	size_t counter = 20;
	double start, finish;
	DiscreteGaussianGeneratorImpl<BigInteger,BigVector> dgg(SIGMA);

	usint sm = SECURE_PARAMS[index].m;
	BigInteger smodulus(SECURE_PARAMS[index].modulus);
	BigInteger srootOfUnity(SECURE_PARAMS[index].rootOfUnity);

	ILParams ilParams(sm, smodulus, srootOfUnity);
	shared_ptr<ILParams> silParams = std::make_shared<ILParams>(ilParams);

	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "base: " << base << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
	DiscreteFourierTransform::PreComputeTable(sm);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

	silParams = std::make_shared<ILParams>(ilParams);
	LPSignatureParameters<Poly> signParams(silParams, dgg, base);
	//signParams.SetElemParams(silParams);
	std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;

	//std::cout << "std = " << signParams.GetDiscreteGaussianGenerator().GetStd() << std::endl;

	LPSignKeyGPVGM<Poly> s_k_gm(signParams);
	LPVerificationKeyGPVGM<Poly> v_k_gm(signParams);
	LPSignatureSchemeGPVGM<Poly> scheme_gm;

	vector<Signature<Matrix<Poly>>> signature(counter);

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

	std::vector<string> text{
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

	Signature<Matrix<Poly>> precompSignature;

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

