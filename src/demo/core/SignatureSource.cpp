#include "../../lib/crypto/signature/lwesign.h"
#include "../../lib/crypto/signature/lwesign.cpp"
#include "../../lib/encoding/byteencoding.h"
#include <vld.h>

using namespace lbcrypto;

int main() {
	double start, finish;
	DiscreteGaussianGenerator dgg(4);
	
	usint sm = 16;
	BigBinaryInteger smodulus("1152921504606847009");
	BigBinaryInteger srootOfUnity("405107564542978792");
	ILParams silParams(sm, smodulus, srootOfUnity);
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
	std::cout << "Key generation for signature: " << "\t" << finish - start << " ms" << std::endl;

	Signature<Matrix<ILVector2n>> signature, signature2;
	ByteArray text("1Sig");
	ByteArray text2("2Sig");

	start = currentDateTime();
	scheme.Sign(s_k, text, &signature);
	scheme.Sign(s_k, text2, &signature2);
	finish = currentDateTime();
	std::cout << "Signing two texts with same key : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text) << std::endl;
	std::cout << "Signature 2-Text 1 verification:" << scheme.Verify(v_k, signature2, text) << std::endl;
	std::cout << "Signature 2-Text 2 verification:" << scheme.Verify(v_k, signature2, text2) << std::endl;
	std::cout << "Signature 1-Text 2 verification:" << scheme.Verify(v_k, signature, text2) << std::endl;
	finish = currentDateTime();
	std::cout << "Verifying 4 signature-text combinations : " << "\t" << finish - start << " ms" << std::endl;
	
	
	/* Not included for performance reasons
	sm = 256;
	smodulus.SetValue("134246401");
	srootOfUnity.SetValue("102389487");
	silParams.SetCyclotomicOrder(sm);
	silParams.SetRootOfUnity(srootOfUnity);
	silParams.SetModulus(smodulus);
	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;


	signParams.SetDiscreteGaussianGenerator(dgg);
	signParams.SetElemParams(silParams);

	s_k.SetSignatureParameters(signParams);
	v_k.SetSignatureParameters(signParams);

	start = currentDateTime();
	scheme.KeyGen(&s_k, &v_k);
	finish = currentDateTime();
	std::cout << "Key generation for signature: " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	scheme.Sign(s_k, text, &signature);
	scheme.Sign(s_k, text2, &signature2);
	finish = currentDateTime();
	std::cout << "Signing two texts with same key : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text) << std::endl;
	std::cout << "Signature 2-Text 1 verification:" << scheme.Verify(v_k, signature2, text) << std::endl;
	std::cout << "Signature 2-Text 2 verification:" << scheme.Verify(v_k, signature2, text2) << std::endl;
	std::cout << "Signature 1-Text 2 verification:" << scheme.Verify(v_k, signature, text2) << std::endl;
	finish = currentDateTime();
	std::cout << "Verifying 4 signature-text combinations : " << "\t" << finish - start << " ms" << std::endl;

	sm = 512;
	smodulus.SetValue("134246401");
	srootOfUnity.SetValue("49884309");
	silParams.SetCyclotomicOrder(sm);
	silParams.SetRootOfUnity(srootOfUnity);
	silParams.SetModulus(smodulus);
	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;


	signParams.SetDiscreteGaussianGenerator(dgg);
	signParams.SetElemParams(silParams);

	s_k.SetSignatureParameters(signParams);
	v_k.SetSignatureParameters(signParams);

	start = currentDateTime();
	scheme.KeyGen(&s_k, &v_k);
	finish = currentDateTime();
	std::cout << "Key generation for signature: " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	scheme.Sign(s_k, text, &signature);
	scheme.Sign(s_k, text2, &signature2);
	finish = currentDateTime();
	std::cout << "Signing two texts with same key : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text) << std::endl;
	std::cout << "Signature 2-Text 1 verification:" << scheme.Verify(v_k, signature2, text) << std::endl;
	std::cout << "Signature 2-Text 2 verification:" << scheme.Verify(v_k, signature2, text2) << std::endl;
	std::cout << "Signature 1-Text 2 verification:" << scheme.Verify(v_k, signature, text2) << std::endl;
	finish = currentDateTime();
	std::cout << "Verifying 4 signature-text combinations : " << "\t" << finish - start << " ms" << std::endl;

	sm = 1024;
	smodulus.SetValue("134246401");
	srootOfUnity.SetValue("122451504");
	silParams.SetCyclotomicOrder(sm);
	silParams.SetRootOfUnity(srootOfUnity);
	silParams.SetModulus(smodulus);
	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;


	signParams.SetDiscreteGaussianGenerator(dgg);
	signParams.SetElemParams(silParams);

	s_k.SetSignatureParameters(signParams);
	v_k.SetSignatureParameters(signParams);

	start = currentDateTime();
	scheme.KeyGen(&s_k, &v_k);
	finish = currentDateTime();
	std::cout << "Key generation for signature: " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	scheme.Sign(s_k, text, &signature);
	scheme.Sign(s_k, text2, &signature2);
	finish = currentDateTime();
	std::cout << "Signing two texts with same key : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text) << std::endl;
	std::cout << "Signature 2-Text 1 verification:" << scheme.Verify(v_k, signature2, text) << std::endl;
	std::cout << "Signature 2-Text 2 verification:" << scheme.Verify(v_k, signature2, text2) << std::endl;
	std::cout << "Signature 1-Text 2 verification:" << scheme.Verify(v_k, signature, text2) << std::endl;
	finish = currentDateTime();
	std::cout << "Verifying 4 signature-text combinations : " << "\t" << finish - start << " ms" << std::endl;

	

	sm = 2048;
	smodulus.SetValue("134246401");
	srootOfUnity.SetValue("34044212");
	silParams.SetCyclotomicOrder(sm);
	silParams.SetRootOfUnity(srootOfUnity);
	silParams.SetModulus(smodulus);
	std::cout << "m: " << sm << " q: " << smodulus << " rootOfUnity: " << srootOfUnity << std::endl;
	std::cout << "Signature precomputations" << std::endl;
	start = currentDateTime();
	ChineseRemainderTransformFTT::GetInstance().PreCompute(srootOfUnity, sm, smodulus);
	ILVector2n::PreComputeDggSamples(dgg, silParams);
	finish = currentDateTime();
	std::cout << "Precomputation time: " << finish - start << " ms" << std::endl;

	signParams.SetDiscreteGaussianGenerator(dgg);
	signParams.SetElemParams(silParams);

	s_k.SetSignatureParameters(signParams);
	v_k.SetSignatureParameters(signParams);

	start = currentDateTime();
	scheme.KeyGen(&s_k, &v_k);
	finish = currentDateTime();
	std::cout << "Key generation for signature: " << "\t" << finish - start << " ms" << std::endl;


	start = currentDateTime();
	scheme.Sign(s_k, text, &signature);
	scheme.Sign(s_k, text2, &signature2);
	finish = currentDateTime();
	std::cout << "Signing two texts with same key : " << "\t" << finish - start << " ms" << std::endl;

	start = currentDateTime();
	std::cout << "Signature 1-Text 1 verification:" << scheme.Verify(v_k, signature, text) << std::endl;
	std::cout << "Signature 2-Text 1 verification:" << scheme.Verify(v_k, signature2, text) << std::endl;
	std::cout << "Signature 2-Text 2 verification:" << scheme.Verify(v_k, signature2, text2) << std::endl;
	std::cout << "Signature 1-Text 2 verification:" << scheme.Verify(v_k, signature, text2) << std::endl;
	finish = currentDateTime();
	std::cout << "Verifying 4 signature-text combinations : " << "\t" << finish - start << " ms" << std::endl;
	*/
	
	
	std::cout << "Execution completed" << std::endl;
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();
	
	return 0;
}
