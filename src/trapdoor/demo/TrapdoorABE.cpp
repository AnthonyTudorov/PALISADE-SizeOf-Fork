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

void MultiThreadedRun(int index);

int main() {

	for (usint i = 0; i < 1; i++) {
		MultiThreadedRun(i);
	}

	DiscreteFourierTransform::Reset();

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
		{ 4096, "1125899906949121", "395927927481109"}, 
		{ 4096, "576460752303439873", "324227211372304498"},
		{ 4096, "295147905179352850433", "38059604470202023702"},
		{ 8192, "2417851639229258349469697", "1609369582361334250296874"},
		{ 8192, "2475880078570760549798338561", "468603779894314640604009508"},
		{ 8192, "2535301200456458802993406697473", "2254011826592167418090798449257"},
		{ 8192, "2596148429267413814265248164724737", "527359281404164400933330593019541"},
		{ 8192, "2658455991569831745807614120560893953", "286795907251575358753455600791011050"},
		{ 8192, "2722258935367507707706996859454146142209", "1426115470453457649704739287701063827541"},
	};


	size_t counter = 24;
	double start, finish;
	DiscreteGaussianGeneratorImpl<BigInteger,BigVector> dgg(SIGMA);

	usint sm = SECURE_PARAMS[index].m;
	BigInteger smodulus(SECURE_PARAMS[index].modulus);
	BigInteger srootOfUnity(SECURE_PARAMS[index].rootOfUnity);

	ILParams ilParams(sm, smodulus, srootOfUnity);
	shared_ptr<ILParams> silParams = std::make_shared<ILParams>(ilParams);

	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
	DiscreteFourierTransform::PreComputeTable(sm);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

	silParams = std::make_shared<ILParams>(ilParams);
	LPSignatureParameters<Poly> signParams(silParams, dgg);
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

