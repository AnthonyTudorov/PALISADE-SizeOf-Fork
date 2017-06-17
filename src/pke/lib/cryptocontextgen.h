/**
 * @file ciphertextgen.h -- Generator for crypto contexts.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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

inline CryptoContext<ILDCRT2n> GenCryptoContextElementArrayNull(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILDCRT2n::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextNull(p, ptm);
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

inline CryptoContext<ILDCRT2n> GenCryptoContextElementArrayLTV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILDCRT2n::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextLTV(p, ptm, 1, 4, ntowers);
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

inline CryptoContext<ILDCRT2n> GenCryptoContextElementArrayStSt(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILDCRT2n::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5, ntowers);
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

inline CryptoContext<ILDCRT2n> GenCryptoContextElementArrayBV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {
	shared_ptr<ILDCRT2n::Params> p = GenerateDCRTParams(ORDER, ptm, ntowers, bits);

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextBV(p, ptm, 1, 3, RLWE, ntowers);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}


inline CryptoContext<ILVector2n> GenCryptoContextElementFV(usint ORDER, usint ptm, usint bits=PrimeBits) {

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);

	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

inline CryptoContext<ILDCRT2n> GenCryptoContextElementArrayFV(usint ORDER, usint ntowers, usint ptm, usint bits=PrimeBits) {

	CryptoContext<ILDCRT2n> cc = CryptoContextFactory<ILDCRT2n>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	return cc;
}

#endif /* SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_ */
