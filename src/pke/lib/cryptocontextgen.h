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
#include "lattice/elemparamfactory.h"

using namespace lbcrypto;

static const usint DefaultPrimeBits = 50;
static const usint DefaultTowers = 3;

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextNull(usint ORDER, usint ptm, usint bits=DefaultPrimeBits, usint towers=DefaultTowers) {
	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params,typename Element::Integer>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextNull(p, ptm);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextLTV(usint ORDER, usint ptm, usint bits=DefaultPrimeBits, usint towers=DefaultTowers) {
	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params,typename Element::Integer>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextLTV(p, ptm, 1, 4);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextStSt(usint ORDER, usint ptm, usint bits=DefaultPrimeBits, usint towers=DefaultTowers) {

	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params,typename Element::Integer>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline CryptoContext<Poly> GenCryptoContextElementBV(usint ORDER, usint ptm, usint bits=DefaultPrimeBits) {
	shared_ptr<Poly::Params> p = ElemParamFactory::GenElemParams<Poly::Params,Poly::Integer>(ORDER);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBV(p, ptm, 1, 4);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextBV(usint ORDER, usint ptm, usint bits=DefaultPrimeBits, usint towers=DefaultTowers) {

	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params,typename Element::Integer>(ORDER, bits, towers);

	CryptoContext<Element> cc = CryptoContextFactory<Element>::genCryptoContextBV(p, ptm, 1, 4);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

inline CryptoContext<DCRTPoly> GenCryptoContextElementArrayBV(usint ORDER, usint ntowers, usint ptm, usint bits=DefaultPrimeBits) {
	shared_ptr<DCRTPoly::Params> p = GenerateDCRTParams(ORDER, ntowers, bits);

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBV(p, ptm, 1, 3, RLWE, ntowers);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}


inline CryptoContext<Poly> GenCryptoContextElementFV(usint ORDER, usint ptm, usint bits=DefaultPrimeBits) {
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);
	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextFV(usint ORDER, usint ptm, usint bits=DefaultPrimeBits, usint towers=DefaultTowers);

template<>
inline CryptoContext<Poly>
GenCryptoContextFV(usint ORDER, usint ptm, usint bits, usint towers) {

	shared_ptr<typename Poly::Params> p = ElemParamFactory::GenElemParams<typename Poly::Params,typename Poly::Integer>(ORDER, bits, towers);

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);
	return cc;
}

template<>
inline CryptoContext<NativePoly>
GenCryptoContextFV(usint ORDER, usint ptm, usint bits, usint towers) {

	shared_ptr<typename NativePoly::Params> p = ElemParamFactory::GenElemParams<typename NativePoly::Params,typename NativePoly::Integer>(ORDER, bits, towers);

	CryptoContext<NativePoly> cc = CryptoContextFactory<NativePoly>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);
	return cc;
}

template<>
inline CryptoContext<DCRTPoly>
GenCryptoContextFV(usint ORDER, usint ptm, usint bits, usint towers) {

	PALISADE_THROW(not_available_error, "DCRT is not supported for FV");
}

inline CryptoContext<DCRTPoly> GenCryptoContextElementArrayFV(usint ORDER, usint ntowers, usint ptm, usint bits=DefaultPrimeBits) {

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextFV(ptm, 1.006, 1, 4, 0, 2, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}

template<typename Element>
inline CryptoContext<Element>
GenCryptoContextBFVrns(usint ORDER, usint ptm, usint bits=DefaultPrimeBits, usint towers=DefaultTowers);

template<>
inline CryptoContext<Poly>
GenCryptoContextBFVrns(usint ORDER, usint ptm, usint bits, usint towers) {

	PALISADE_THROW(not_available_error, "Poly is not supported for BFVrns");
}

template<>
inline CryptoContext<NativePoly>
GenCryptoContextBFVrns(usint ORDER, usint ptm, usint bits, usint towers) {

	PALISADE_THROW(not_available_error, "NativePoly is not supported for BFVrns");
}

template<>
inline CryptoContext<DCRTPoly>
GenCryptoContextBFVrns(usint ORDER, usint ptm, usint bits, usint towers) {
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(ptm, 1.006, 1, 4, 0, 2, 0);
	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}


template<typename Element>
inline CryptoContext<Element>
GenTestCryptoContext(const string& name, usint ORDER, usint ptm, usint bits=DefaultPrimeBits, usint towers=DefaultTowers) {
	shared_ptr<typename Element::Params> p = ElemParamFactory::GenElemParams<typename Element::Params,typename Element::Integer>(ORDER, bits, towers);
	CryptoContext<Element> cc;

	if( name == "Null" )
		cc = CryptoContextFactory<Element>::genCryptoContextNull(p, ptm);
	else if( name == "LTV" )
		cc = CryptoContextFactory<Element>::genCryptoContextLTV(p, ptm, 1, 4);
	else if( name == "StSt" )
		cc = CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(p, ptm, 1, 4, 41411.5);
	else if( name == "BV" )
		cc = CryptoContextFactory<Element>::genCryptoContextBV(p, ptm, 1, 4);
	else if( name == "FV" )
		cc = GenCryptoContextFV<Element>(ORDER, ptm, bits, towers);
	else if( name == "BFVrns" )
		cc = GenCryptoContextBFVrns<Element>(ORDER, ptm, bits, towers);
	else {
		cout << "nothing for " << name << endl;
		PALISADE_THROW(not_available_error, "No generator for " + name);
	}

	cc->Enable(ENCRYPTION);
	cc->Enable(PRE);
	cc->Enable(SHE);

	return cc;
}


#endif /* SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_ */
