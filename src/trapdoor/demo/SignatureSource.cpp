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
#include "utils/serializablehelper.h"

#include <omp.h> //open MP header

//#define ONLINE_TIMING 1
//#define OFFLINE_TIMING 1
using namespace lbcrypto;

void SingleThreadedRun();
void MultiThreadedRun();

int main() {
	//SingleThreadedRun();
	MultiThreadedRun();
	return 0;
}

void MultiThreadedRun() {

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

	size_t counter = 50;
	double start, finish;
	DiscreteGaussianGeneratorImpl<BigVector> dgg(SIGMA);

	usint sm = 2048;
	BigInteger smodulus("67127297");
	BigInteger srootOfUnity("19715182");

	ILParams ilParams(sm, smodulus, srootOfUnity);
	shared_ptr<ILParams> silParams = std::make_shared<ILParams>(ilParams);

	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
	DiscreteFourierTransform::PreComputeTable(sm);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

	usint base = 2;

	silParams = std::make_shared<ILParams>(ilParams);
	LPSignatureParameters<Poly> signParams(silParams, dgg, base);
signParams.SetElemParams(silParams);
	std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;

	LPSignKeyGPVGM<Poly> s_k_gm(signParams);
	LPVerificationKeyGPVGM<Poly> v_k_gm(signParams);
	LPSignatureSchemeGPVGM<Poly> scheme_gm;

	vector<Signature<Matrix<Poly>>> signature(counter);

	scheme_gm.KeyGen(&s_k_gm, &v_k_gm);

	start = currentDateTime();
	scheme_gm.KeyGen(&s_k_gm, &v_k_gm);
	finish = currentDateTime();
	std::cout << "Key generation - New : " << "\t" << finish - start << " ms" << std::endl;

	/////////////////////////////// FOR YURIY
	std::cout << "serializing matrix in LPSignKeyGPVGM" << std::endl;
	Serialized ser;
	std::string stringSer;

Matrix<Poly> publicKey = s_k_gm.GetPrivateElement().first;
publicKey.SwitchFormat();

	publicKey.Serialize(&ser);
	SerializableHelper::SerializationToString(ser,stringSer);
	//std::cout << stringSer << std::endl;
	std::cout << "Length of public key is " << stringSer.length() << std::endl;

Matrix<Poly> privateKey1 = s_k_gm.GetPrivateElement().second.m_e;
privateKey1.SwitchFormat();

	privateKey1.Serialize(&ser);
	SerializableHelper::SerializationToString(ser,stringSer);
	//std::cout << stringSer << std::endl;
	std::cout << "Length of private key 1 is " << stringSer.length() << std::endl;

Matrix<Poly> privateKey2 = s_k_gm.GetPrivateElement().second.m_r;
privateKey2.SwitchFormat();

	privateKey2.Serialize(&ser);
	SerializableHelper::SerializationToString(ser,stringSer);
	//std::cout << stringSer << std::endl;
	std::cout << "Length of private key 2 is " << stringSer.length() << std::endl;

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

	start = currentDateTime();

#pragma omp parallel for
	for (usint i = 0; i < counter; i++) {

		scheme_gm.Sign(s_k_gm, text[i % 10], &(signature[i]));

	}
		
	finish = currentDateTime();

	signTime = finish - start;

	std::cout << "Signing - New : " << "\t" << signTime / counter << " ms" << std::endl;

	start = currentDateTime();

#pragma omp parallel for
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
	DiscreteFourierTransform::Reset();

}

void SingleThreadedRun() {

		size_t counter = 10;
		double start, finish;
		Poly::DggType dgg(SIGMA);
		usint sm = 16;
		BigInteger smodulus("1048609");
		BigInteger srootOfUnity("389832");
		ILParams ilParams(sm, smodulus, srootOfUnity);
		shared_ptr<ILParams> silParams = std::make_shared<ILParams>(ilParams);
		start = currentDateTime();
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		finish = currentDateTime();
		std::cout << "Signature precomputations" << std::endl;
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);
		std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;
		LPSignatureParameters<Poly> signParams(silParams, dgg);
		//LPSignKeyGPV<Poly> s_k(signParams);
		//LPVerificationKeyGPV<Poly> v_k(signParams);
		//LPSignatureSchemeGPV<Poly> scheme;
		start = currentDateTime();
		//scheme.KeyGen(&s_k, &v_k);
		finish = currentDateTime();
		std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;

		std::cout << "Test" << std::endl;
		Signature<Matrix<Poly>> signature, signature2;

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

		start = currentDateTime();
		//scheme.Sign(s_k, text[0], &signature);
		finish = currentDateTime();
		std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

		start = currentDateTime();
		//std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
		finish = currentDateTime();
		std::cout << "Verifying - Old : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		LPSignKeyGPVGM<Poly> s_k_gm(signParams);
		LPVerificationKeyGPVGM<Poly> v_k_gm(signParams);
		LPSignatureSchemeGPVGM<Poly> scheme_gm;
		start = currentDateTime();
		scheme_gm.KeyGen(&s_k_gm, &v_k_gm);
		finish = currentDateTime();
		std::cout << "Key generation - New : " << "\t" << finish - start << " ms" << std::endl;


		start = currentDateTime();
		scheme_gm.Sign(s_k_gm, text[0], &signature);
		finish = currentDateTime();
		std::cout << "Signing - New : " << "\t" << finish - start << " ms" << std::endl;

		start = currentDateTime();
		std::cout << "Signature 1-Text 1 verification:" << scheme_gm.Verify(v_k_gm, signature, text[0]) << std::endl;
		finish = currentDateTime();
		std::cout << "Verifying - New : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		/*
		sm = 256;
		smodulus.SetValue("134246401");
		srootOfUnity.SetValue("102389487");
		ilParams.SetCyclotomicOrder(sm);
		ilParams.SetRootOfUnity(srootOfUnity);
		ilParams.SetModulus(smodulus);
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		std::cout << "Signature precomputations" << std::endl;
		start = currentDateTime();
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
		finish = currentDateTime();
		std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

		silParams = std::make_shared<ILParams>(ilParams);
		signParams.SetElemParams(silParams);
		std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl<<std::endl;
		s_k.SetSignatureParameters(signParams);
		v_k.SetSignatureParameters(signParams);

		start = currentDateTime();
		scheme.KeyGen(&s_k, &v_k);
		finish = currentDateTime();
		std::cout << "Key generation  - Old : " << "\t" << finish - start << " ms" << std::endl;

		start = currentDateTime();
		scheme.Sign(s_k, text, &signature);
		finish = currentDateTime();
		std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

		start = currentDateTime();
		std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text) << std::endl;
		finish = currentDateTime();
		std::cout << "Verifying - Old : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		s_k_gm.SetSignatureParameters(signParams);
		v_k_gm.SetSignatureParameters(signParams);

		start = currentDateTime();
		scheme_gm.KeyGen(&s_k_gm, &v_k_gm);
		finish = currentDateTime();
		std::cout << "Key generation  - New : " << "\t" << finish - start << " ms" << std::endl;

		start = currentDateTime();
		scheme_gm.Sign(s_k_gm, text, &signature);
		finish = currentDateTime();
		std::cout << "Signing - New : " << "\t" << finish - start << " ms" << std::endl;

		start = currentDateTime();
		std::cout << "Signature 1-Text 1 verification:" << scheme_gm.Verify(v_k_gm, signature, text) << std::endl;
		finish = currentDateTime();
		std::cout << "Verifying - New : " << "\t" << finish - start << " ms" << std::endl << std::endl;
		*/

		sm = 512;
		smodulus.SetValue("134246401");
		srootOfUnity.SetValue("49884309");
		ilParams = ILParams(sm, smodulus, srootOfUnity);
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		std::cout << "Signature precomputations" << std::endl;
		start = currentDateTime();
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);
		finish = currentDateTime();
		std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

		silParams = std::make_shared<ILParams>(ilParams);
		signParams.SetElemParams(silParams);
		std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;
		//s_k.SetSignatureParameters(signParams);
		//v_k.SetSignatureParameters(signParams);

		//start = currentDateTime();
		//scheme.KeyGen(&s_k, &v_k);
		//finish = currentDateTime();
		//std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;

		//start = currentDateTime();
		//scheme.Sign(s_k, text[0], &signature);
		//finish = currentDateTime();
		//std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

		//start = currentDateTime();
		//std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
		//finish = currentDateTime();
		//std::cout << "Verifying -Old : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		s_k_gm.SetSignatureParameters(signParams);
		v_k_gm.SetSignatureParameters(signParams);

		start = currentDateTime();
		scheme_gm.KeyGen(&s_k_gm, &v_k_gm);
		finish = currentDateTime();
		std::cout << "Key generation - New : " << "\t" << finish - start << " ms" << std::endl;

		double signTime = 0;
		double verifyTime = 0;
		size_t verifyCounter = 0;
		bool verifyBool = false;

		for (usint i = 0; i < counter; i++) {

			start = currentDateTime();
			scheme_gm.Sign(s_k_gm, text[i], &signature);
			finish = currentDateTime();

			signTime += finish - start;
			//std::cout << "Signing - New : " << "\t" << finish - start << " ms" << std::endl;

			start = currentDateTime();
			verifyBool = scheme_gm.Verify(v_k_gm, signature, text[i]);
			finish = currentDateTime();

			verifyTime += finish - start;

			if (verifyBool)
				verifyCounter++;
			//std::cout << "Verifying - New : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		}

		std::cout << "Signing - New : " << "\t" << signTime / counter << " ms" << std::endl;
		std::cout << "Verifying - New : " << "\t" << verifyTime / counter << " ms" << std::endl;
		std::cout << "Verification counter : " << "\t" << verifyCounter << "\n" << std::endl;

		sm = 1024;
		smodulus.SetValue("134246401");
		srootOfUnity.SetValue("122451504");
		ilParams = ILParams(sm, smodulus, srootOfUnity);
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		std::cout << "Signature precomputations" << std::endl;
		start = currentDateTime();
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);
		finish = currentDateTime();
		std::cout << "Precomputation time: " << finish - start << " ms" << std::endl << std::endl;


		silParams = std::make_shared<ILParams>(ilParams);
		signParams.SetElemParams(silParams);
		std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;
		//s_k.SetSignatureParameters(signParams);
		//v_k.SetSignatureParameters(signParams);

		//start = currentDateTime();
		//scheme.KeyGen(&s_k, &v_k);
		//finish = currentDateTime();
		//std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;

		//start = currentDateTime();
		//scheme.Sign(s_k, text[0], &signature);
		//finish = currentDateTime();
		//std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

		//start = currentDateTime();
		//std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
		//finish = currentDateTime();
		//std::cout << "Verifying - Old : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		s_k_gm.SetSignatureParameters(signParams);
		v_k_gm.SetSignatureParameters(signParams);

		start = currentDateTime();
		scheme_gm.KeyGen(&s_k_gm, &v_k_gm);
		finish = currentDateTime();
		std::cout << "Key generation - New : " << "\t" << finish - start << " ms" << std::endl;

		signTime = 0;
		verifyTime = 0;
		verifyCounter = 0;
		verifyBool = false;

		for (usint i = 0; i < counter; i++) {

			start = currentDateTime();
			scheme_gm.Sign(s_k_gm, text[0], &signature);
			finish = currentDateTime();

			signTime += finish - start;
			//std::cout << "Signing - New : " << "\t" << finish - start << " ms" << std::endl;

			start = currentDateTime();
			verifyBool = scheme_gm.Verify(v_k_gm, signature, text[0]);
			finish = currentDateTime();

			verifyTime += finish - start;

			if (verifyBool)
				verifyCounter++;
			//std::cout << "Verifying - New : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		}

		std::cout << "Signing - New : " << "\t" << signTime / counter << " ms" << std::endl;
		std::cout << "Verifying - New : " << "\t" << verifyTime / counter << " ms" << std::endl;
		std::cout << "Verification counter : " << "\t" << verifyCounter << "\n" << std::endl;

		sm = 2048;
		smodulus.SetValue("134246401");
		srootOfUnity.SetValue("34044212");
		ilParams = ILParams(sm, smodulus, srootOfUnity);
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		std::cout << "Signature precomputations" << std::endl;
		start = currentDateTime();
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::PreComputeTable(sm);
		finish = currentDateTime();
		std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

		silParams = std::make_shared<ILParams>(ilParams);
		signParams.SetElemParams(silParams);
		std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;
		//s_k.SetSignatureParameters(signParams);
		//v_k.SetSignatureParameters(signParams);

		//start = currentDateTime();
		//scheme.KeyGen(&s_k, &v_k);
		//finish = currentDateTime();
		//std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;


		//start = currentDateTime();
		//scheme.Sign(s_k, text[0], &signature);
		//finish = currentDateTime();
		//std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

		//start = currentDateTime();
		//std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
		//finish = currentDateTime();
		//std::cout << "Verifying - Old : " << "\t" << finish - start << " ms" << std::endl;

		s_k_gm.SetSignatureParameters(signParams);
		v_k_gm.SetSignatureParameters(signParams);

		start = currentDateTime();
		scheme_gm.KeyGen(&s_k_gm, &v_k_gm);
		finish = currentDateTime();
		std::cout << "Key generation - New : " << "\t" << finish - start << " ms" << std::endl;

		signTime = 0;
		verifyTime = 0;
		verifyCounter = 0;
		verifyBool = false;

		for (usint i = 0; i < counter; i++) {

			start = currentDateTime();
			scheme_gm.Sign(s_k_gm, text[0], &signature);
			finish = currentDateTime();

			signTime += finish - start;
			//std::cout << "Signing - New : " << "\t" << finish - start << " ms" << std::endl;

			start = currentDateTime();
			verifyBool = scheme_gm.Verify(v_k_gm, signature, text[0]);
			finish = currentDateTime();

			verifyTime += finish - start;

			if (verifyBool)
				verifyCounter++;
			//std::cout << "Verifying - New : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		}

		std::cout << "Signing - New : " << "\t" << signTime / counter << " ms" << std::endl;
		std::cout << "Verifying - New : " << "\t" << verifyTime / counter << " ms" << std::endl;
		std::cout << "Verification counter : " << "\t" << verifyCounter << "\n" << std::endl;

		std::cout << "Execution completed" << std::endl;
		DiscreteFourierTransform::Reset();

		//std::cin.ignore();
		//std::cin.get();


}
