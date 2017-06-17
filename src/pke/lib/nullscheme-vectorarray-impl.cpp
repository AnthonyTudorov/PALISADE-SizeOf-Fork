/*
 * @file nullscheme-vectorarray-impl.cpp - null scheme vector array implementation
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

#include "cryptocontext.h"
#include "nullscheme.h"

namespace lbcrypto {

template<>
shared_ptr<Ciphertext<ILDCRT2n>> LPAlgorithmSHENull<ILDCRT2n>::EvalMult(const shared_ptr<Ciphertext<ILDCRT2n>> ciphertext1,
	const shared_ptr<Ciphertext<ILDCRT2n>> ciphertext2) const {

	shared_ptr<Ciphertext<ILDCRT2n>> newCiphertext(new Ciphertext<ILDCRT2n>(ciphertext2->GetCryptoContext()));

	const ILDCRT2n& c1 = ciphertext1->GetElement();
	const ILDCRT2n& c2 = ciphertext2->GetElement();

	const vector<typename ILDCRT2n::ILVectorType>& c1e = c1.GetAllElements();
	const vector<typename ILDCRT2n::ILVectorType>& c2e = c2.GetAllElements();

	const BigBinaryInteger& ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

	vector<typename ILDCRT2n::ILVectorType> mResults;

	for( size_t i = 0; i < c1.GetNumOfElements(); i++ ) {
		typename ILDCRT2n::ILVectorType v = ElementNullSchemeMultiply(c1e.at(i), c2e.at(i), ptm);
		mResults.push_back(v);
	}

	ILDCRT2n	cResult(mResults);

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template class LPCryptoParametersNull<ILDCRT2n>;
template class LPPublicKeyEncryptionSchemeNull<ILDCRT2n>;
template class LPAlgorithmNull<ILDCRT2n>;
}
