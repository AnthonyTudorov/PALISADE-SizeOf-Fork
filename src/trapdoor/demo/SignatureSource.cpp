#include "signature/lwesign.h"
#include "signature/lwesign.cpp"
#include "encoding/byteplaintextencoding.h"
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
	DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector> dgg(SIGMA);

	usint sm = 2048;
	BigBinaryInteger smodulus("67127297");
	BigBinaryInteger srootOfUnity("19715182");

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

	LPSignKeyGPVGM<ILVector2n> s_k_gm(signParams);
	LPVerificationKeyGPVGM<ILVector2n> v_k_gm(signParams);
	LPSignatureSchemeGPVGM<ILVector2n> scheme_gm;

	vector<Signature<Matrix<ILVector2n>>> signature(counter);

	scheme_gm.KeyGen(&s_k_gm, &v_k_gm);

	start = currentDateTime();
	scheme_gm.KeyGen(&s_k_gm, &v_k_gm);
	finish = currentDateTime();
	std::cout << "Key generation - New : " << "\t" << finish - start << " ms" << std::endl;

	/////////////////////////////// FOR YURIY
	std::cout << "serializing matrix in LPSignKeyGPVGM" << std::endl;
	Serialized ser;
	std::string stringSer;

Matrix<ILVector2n> publicKey = s_k_gm.GetPrivateElement().first;
publicKey.SwitchFormat();

	publicKey.Serialize(&ser);
	SerializableHelper::SerializationToString(ser,stringSer);
	//std::cout << stringSer << std::endl;
	std::cout << "Length of public key is " << stringSer.length() << std::endl;

Matrix<ILVector2n> privateKey1 = s_k_gm.GetPrivateElement().second.m_e;
privateKey1.SwitchFormat();

	privateKey1.Serialize(&ser);
	SerializableHelper::SerializationToString(ser,stringSer);
	//std::cout << stringSer << std::endl;
	std::cout << "Length of private key 1 is " << stringSer.length() << std::endl;

Matrix<ILVector2n> privateKey2 = s_k_gm.GetPrivateElement().second.m_r;
privateKey2.SwitchFormat();

	privateKey2.Serialize(&ser);
	SerializableHelper::SerializationToString(ser,stringSer);
	//std::cout << stringSer << std::endl;
	std::cout << "Length of private key 2 is " << stringSer.length() << std::endl;

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
	ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().Destroy();
	NumberTheoreticTransform<BigBinaryInteger,BigBinaryVector>::GetInstance().Destroy();
	DiscreteFourierTransform::GetInstance().Destroy();

}

void SingleThreadedRun() {

		size_t counter = 10;
		double start, finish;
		ILVector2n::DggType dgg(SIGMA);
		usint sm = 16;
		BigBinaryInteger smodulus("1048609");
		BigBinaryInteger srootOfUnity("389832");
		ILParams ilParams(sm, smodulus, srootOfUnity);
		shared_ptr<ILParams> silParams = std::make_shared<ILParams>(ilParams);
		start = currentDateTime();
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		finish = currentDateTime();
		std::cout << "Signature precomputations" << std::endl;
		ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
		DiscreteFourierTransform::GetInstance().PreComputeTable(sm);
		ILVector2n::PreComputeDggSamples(dgg, silParams);
		std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;
		LPSignatureParameters signParams(silParams, dgg);
		//LPSignKeyGPV<ILVector2n> s_k(signParams);
		//LPVerificationKeyGPV<ILVector2n> v_k(signParams);
		//LPSignatureSchemeGPV<ILVector2n> scheme;
		start = currentDateTime();
		//scheme.KeyGen(&s_k, &v_k);
		finish = currentDateTime();
		std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;

		std::cout << "Test" << std::endl;
		Signature<Matrix<ILVector2n>> signature, signature2;

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

		start = currentDateTime();
		//scheme.Sign(s_k, text[0], &signature);
		finish = currentDateTime();
		std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

		start = currentDateTime();
		//std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
		finish = currentDateTime();
		std::cout << "Verifying - Old : " << "\t" << finish - start << " ms" << std::endl << std::endl;

		LPSignKeyGPVGM<ILVector2n> s_k_gm(signParams);
		LPVerificationKeyGPVGM<ILVector2n> v_k_gm(signParams);
		LPSignatureSchemeGPVGM<ILVector2n> scheme_gm;
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
		ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
		ILVector2n::PreComputeDggSamples(dgg, silParams);
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
		ilParams.SetCyclotomicOrder(sm);
		ilParams.SetRootOfUnity(srootOfUnity);
		ilParams.SetModulus(smodulus);
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		std::cout << "Signature precomputations" << std::endl;
		start = currentDateTime();
		ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
		ILVector2n::PreComputeDggSamples(dgg, silParams);
		DiscreteFourierTransform::GetInstance().PreComputeTable(sm);
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
		ilParams.SetCyclotomicOrder(sm);
		ilParams.SetRootOfUnity(srootOfUnity);
		ilParams.SetModulus(smodulus);
		std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
		std::cout << "Signature precomputations" << std::endl;
		start = currentDateTime();
		ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
		ILVector2n::PreComputeDggSamples(dgg, silParams);
		DiscreteFourierTransform::GetInstance().PreComputeTable(sm);
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
		ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().Destroy();
		NumberTheoreticTransform<BigBinaryInteger,BigBinaryVector>::GetInstance().Destroy();
		DiscreteFourierTransform::GetInstance().Destroy();

		//std::cin.ignore();
		//std::cin.get();


}
