#include "signature/lwesign.h"
#include "signature/lwesign.cpp"
#include "encoding/byteplaintextencoding.h"

//#define ONLINE_TIMING 1
//#define OFFLINE_TIMING 1
using namespace lbcrypto;

int main() {
	size_t counter = 10;
	double start, finish;
	DiscreteGaussianGenerator dgg(4);
	usint sm = 16;
	BigBinaryInteger smodulus("1048609");
	BigBinaryInteger srootOfUnity("389832");
	ILParams ilParams(sm, smodulus, srootOfUnity);
	shared_ptr<ILParams> silParams = std::make_shared<ILParams>(ilParams);
	start = currentDateTime();
	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	finish = currentDateTime();
	std::cout << "Signature precomputations" << std::endl;
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;
	LPSignatureParameters signParams(silParams, dgg);
	LPSignKeyGPV<ILVector2n> s_k(signParams);
	LPVerificationKeyGPV<ILVector2n> v_k(signParams);
	LPSignatureSchemeGPV<ILVector2n> scheme;
	start = currentDateTime();
	scheme.KeyGen(&s_k, &v_k);
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
	scheme.Sign(s_k, text[0], &signature);
	finish = currentDateTime();
	std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
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
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
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
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

	silParams = std::make_shared<ILParams>(ilParams);
	signParams.SetElemParams(silParams);
	std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;
	s_k.SetSignatureParameters(signParams);
	v_k.SetSignatureParameters(signParams);

	start = currentDateTime();
	scheme.KeyGen(&s_k, &v_k);
	finish = currentDateTime();
	std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	scheme.Sign(s_k, text[0], &signature);
	finish = currentDateTime();
	std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
	finish = currentDateTime();
	std::cout << "Verifying -Old : " << "\t" << finish - start << " ms" << std::endl << std::endl;

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

	std::cout << "Signing - New : " << "\t" << signTime/counter << " ms" << std::endl;
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
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl << std::endl;


	silParams = std::make_shared<ILParams>(ilParams);
	signParams.SetElemParams(silParams);
	std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;
	s_k.SetSignatureParameters(signParams);
	v_k.SetSignatureParameters(signParams);

	start = currentDateTime();
	scheme.KeyGen(&s_k, &v_k);
	finish = currentDateTime();
	std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	scheme.Sign(s_k, text[0], &signature);
	finish = currentDateTime();
	std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text[0]) << std::endl;
	finish = currentDateTime();
	std::cout << "Verifying - Old : " << "\t" << finish - start << " ms" << std::endl << std::endl;

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
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

	silParams = std::make_shared<ILParams>(ilParams);
	signParams.SetElemParams(silParams);
	std::cout << signParams.GetILParams()->GetCyclotomicOrder() << std::endl << std::endl;
	s_k.SetSignatureParameters(signParams);
	v_k.SetSignatureParameters(signParams);

	//start = currentDateTime();
	//scheme.KeyGen(&s_k, &v_k);
	//finish = currentDateTime();
	//std::cout << "Key generation - Old : " << "\t" << finish - start << " ms" << std::endl;


	//start = currentDateTime();
	//scheme.Sign(s_k, text, &signature);
	//finish = currentDateTime();
	//std::cout << "Signing - Old : " << "\t" << finish - start << " ms" << std::endl;

	//start = currentDateTime();
	//std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text) << std::endl;
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
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	//std::cin.ignore();
	//std::cin.get();
	
	return 0;
}
