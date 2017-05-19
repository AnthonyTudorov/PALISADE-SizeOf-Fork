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
