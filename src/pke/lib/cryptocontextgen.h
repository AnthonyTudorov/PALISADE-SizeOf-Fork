/*
 * cryptocontextgen.h
 *
 *  Created on: Apr 16, 2017
 *      Author: gerardryan
 */

#ifndef SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_
#define SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_

#include "palisade.h"
#include "cryptocontext.h"
#include "utils/parmfactory.h"

using namespace lbcrypto;

static const usint PrimeBits = 50;

inline CryptoContext<ILVector2n> GenCryptoContextElementNull(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVector2n::Params> p = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(ORDER, bits);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextNull(p, ptm);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILVectorArray2n> GenCryptoContextElementArrayNull(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVectorArray2n::Params> p = GenerateDCRTParams(ORDER, ntowers, bits);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextNull(p, ptm);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILVector2n> GenCryptoContextElementLTV(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVector2n::Params> p = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(ORDER, bits);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(p, ptm, 1, 4);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILVectorArray2n> GenCryptoContextElementArrayLTV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVectorArray2n::Params> p = GenerateDCRTParams(ORDER, ntowers, bits);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextLTV(p, ptm, 1, 4, ntowers);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILVector2n> GenCryptoContextElementStSt(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVector2n::Params> p = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(ORDER, bits);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILVectorArray2n> GenCryptoContextElementArrayStSt(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVectorArray2n::Params> p = GenerateDCRTParams(ORDER, ntowers, bits);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5, ntowers);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILVector2n> GenCryptoContextElementBV(usint ORDER, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVector2n::Params> p = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(ORDER, bits);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(p, ptm, 1, 4);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILVectorArray2n> GenCryptoContextElementArrayBV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVectorArray2n::Params> p = GenerateDCRTParams(ORDER, ntowers, bits);

	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextBV(p, ptm, 1, 3, RLWE, ntowers);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}


inline CryptoContext<ILVector2n> GenCryptoContextElementFV(usint ORDER, usint ptm, usint bits=PrimeBits) {

	shared_ptr<ILVector2n::Params> p = GenerateTestParams<ILVector2n::Params,ILVector2n::Integer>(ORDER, bits);

//    BigBinaryInteger bigModulus = FindPrimeModulus<ILVector2n::Integer>(2 * ORDER, 2*(ceil(log2(p->GetModulus())) + 1) + ceil(log2(ptm)) + 3);
    BigBinaryInteger bigModulus = FindPrimeModulus<ILVector2n::Integer>(2 * ORDER, 2*bits + ceil(log2(ptm)) + 3);
    BigBinaryInteger bigRootOfUnity = RootOfUnity<ILVector2n::Integer>(2 * ORDER, bigModulus);

	BigBinaryInteger plaintextModulus(ptm);

	float stdDev = 4;

	//Set crypto parametes
	BigBinaryInteger delta(p->GetModulus().DividedBy(plaintextModulus));
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
		p, ptm,
		16, stdDev, delta.ToString(), RLWE, bigModulus.ToString(),
		bigRootOfUnity.ToString(), 0, 9, 1.006);

	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);
	std::cout << *cc.GetCryptoParameters() << std::endl;

	return cc;
}

inline CryptoContext<ILVectorArray2n> GenCryptoContextElementArrayFV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILVectorArray2n::Params> p = GenerateDCRTParams(ORDER, ntowers, bits);

	string delta( p->GetModulus().DividedBy(ILVector2n::Integer(ptm)).ToString() );
	CryptoContext<ILVectorArray2n> cc = CryptoContextFactory<ILVectorArray2n>::genCryptoContextFV(p, ptm, 1, 4, delta, RLWE, "0", "0", 0, 9, 1.006);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);
	std::cout << *cc.GetCryptoParameters() << std::endl;

	return cc;
}

#endif /* SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_ */
