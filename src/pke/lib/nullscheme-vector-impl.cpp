/*
* @file nullscheme-vector-impl.cpp - null scheme vector array implementation
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
shared_ptr<Ciphertext<Poly>> LPAlgorithmSHENull<Poly>::EvalMult(const shared_ptr<Ciphertext<Poly>> ciphertext1,
	const shared_ptr<Ciphertext<Poly>> ciphertext2) const {

	shared_ptr<Ciphertext<Poly>> newCiphertext = ciphertext1->CloneEmpty();

	const Poly& c1 = ciphertext1->GetElement();
	const Poly& c2 = ciphertext2->GetElement();

	const BigInteger& ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

	Poly cResult = ElementNullSchemeMultiply(c1, c2, ptm);

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template<>
shared_ptr<Ciphertext<Poly>> LPAlgorithmSHENull<Poly>::EvalMult(const shared_ptr<Ciphertext<Poly>> ciphertext1,
	const shared_ptr<Plaintext> plaintext) const {

	shared_ptr<Ciphertext<Poly>> newCiphertext = ciphertext1->CloneEmpty();

	const Poly& c1 = ciphertext1->GetElement();
	const Poly& c2 = plaintext->GetEncodedElement<Poly>();

	const BigInteger& ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

	Poly cResult = ElementNullSchemeMultiply(c1, c2, ptm);

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template class LPCryptoParametersNull<Poly>;
template class LPPublicKeyEncryptionSchemeNull<Poly>;
template class LPAlgorithmNull<Poly>;
}
