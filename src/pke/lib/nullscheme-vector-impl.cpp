/*
 * nullscheme-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "nullscheme.h"

namespace lbcrypto {

template<>
shared_ptr<Ciphertext<ILVector2n>> LPAlgorithmSHENull<ILVector2n>::EvalMult(const shared_ptr<Ciphertext<ILVector2n>> ciphertext1,
	const shared_ptr<Ciphertext<ILVector2n>> ciphertext2) const {

	shared_ptr<Ciphertext<ILVector2n>> newCiphertext(new Ciphertext<ILVector2n>(ciphertext2->GetCryptoContext()));

	const ILVector2n& c1 = ciphertext1->GetElement();
	const ILVector2n& c2 = ciphertext2->GetElement();

	const BigBinaryInteger& ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

	ILVector2n cResult = ElementNullSchemeMultiply(c1, c2, ptm);

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template class LPCryptoParametersNull<ILVector2n>;
template class LPPublicKeyEncryptionSchemeNull<ILVector2n>;
template class LPAlgorithmNull<ILVector2n>;
}
