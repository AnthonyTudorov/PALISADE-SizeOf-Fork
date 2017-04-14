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
shared_ptr<Ciphertext<ILVectorArray2n>> LPAlgorithmSHENull<ILVectorArray2n>::EvalMult(const shared_ptr<Ciphertext<ILVectorArray2n>> ciphertext1,
	const shared_ptr<Ciphertext<ILVectorArray2n>> ciphertext2) const {

	shared_ptr<Ciphertext<ILVectorArray2n>> newCiphertext(new Ciphertext<ILVectorArray2n>(ciphertext2->GetCryptoContext()));

	const ILVectorArray2n& c1 = ciphertext1->GetElement();
	const ILVectorArray2n& c2 = ciphertext2->GetElement();

	const vector<typename ILVectorArray2n::ILVectorType>& c1e = c1.GetAllElements();
	const vector<typename ILVectorArray2n::ILVectorType>& c2e = c2.GetAllElements();

	const BigBinaryInteger& ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

	vector<typename ILVectorArray2n::ILVectorType> mResults;

	for( int i = 0; i < c1.GetNumOfElements(); i++ ) {
		typename ILVectorArray2n::ILVectorType v = ElementNullSchemeMultiply(c1e.at(i), c2e.at(i), ptm);
		std::cout << "Vector " << i << " mult is " << v << std::endl;
		mResults.push_back(v);
	}

	ILVectorArray2n	cResult(mResults);

	std::cout << cResult << std::endl;

	newCiphertext->SetElement(cResult);

	return newCiphertext;
}

template class LPCryptoParametersNull<ILVectorArray2n>;
template class LPPublicKeyEncryptionSchemeNull<ILVectorArray2n>;
template class LPAlgorithmNull<ILVectorArray2n>;
}
