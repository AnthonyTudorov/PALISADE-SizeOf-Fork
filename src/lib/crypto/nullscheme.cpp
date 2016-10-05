/*
 * nullscheme.cpp
 *
 *  Created on: Oct 4, 2016
 *      Author: gwryan
 */

#include "nullscheme.h"

namespace lbcrypto {

template <class Element>
LPKeyPair<Element> LPAlgorithmNull<Element>::KeyGen(const CryptoContext<Element> cc) const
{
	LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

	Element a(cc.GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);
	kp.secretKey->SetPrivateElement(a);
	kp.publicKey->SetPublicElementAtIndex(0, a);
	kp.publicKey->SetPublicElementAtIndex(1, a);

	return kp;
}

template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmNull<Element>::Encrypt(const shared_ptr<LPPublicKey<Element>> pubKey,
		Element &plaintext) const
		{
	shared_ptr<Ciphertext<Element>> ciphertext( new Ciphertext<Element>(pubKey->GetCryptoContext()) );

	const Element copyPlain = plaintext;
	ciphertext->SetElement(copyPlain);
	ciphertext->SetNorm(BigBinaryInteger::ONE);

	return ciphertext;
		}

template <class Element>
DecryptResult LPAlgorithmNull<Element>::Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Element *plaintext) const
		{
	const Element c = ciphertext->GetElement();
	*plaintext = c;
	return DecryptResult(plaintext->GetLength());
		}

template <class Element>
shared_ptr<LPEvalKey<Element>> LPAlgorithmPRENull<Element>::ReKeyGen(const shared_ptr<LPKey<Element>> newSK,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const
		{
	// create a new ReKey of the proper type, in this context
	shared_ptr<LPEvalKeyNTRURelin<Element>> EK( new LPEvalKeyNTRURelin<Element>(newSK->GetCryptoContext()) );

	Element a(newSK->GetCryptoContext().GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);
	vector<Element> evalKeyElements;
	evalKeyElements.push_back(a);

	EK->SetAVector(std::move(evalKeyElements));

	return EK;

		}

//Function for re-encypting ciphertext using the arrays generated by ReKeyGen
template <class Element>
shared_ptr<Ciphertext<Element>> LPAlgorithmPRENull<Element>::ReEncrypt(const shared_ptr<LPEvalKey<Element>> EK,
		const shared_ptr<Ciphertext<Element>> ciphertext) const
		{
	shared_ptr<Ciphertext<Element>> newCiphertext( new Ciphertext<Element>(*ciphertext) );
	return newCiphertext;
		}

template <class Element>
shared_ptr<Ciphertext<Element>>
LPAlgorithmSHENull<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
		{
	if(ciphertext1->GetElement().GetFormat() == Format::COEFFICIENT || ciphertext2->GetElement().GetFormat() == Format::COEFFICIENT){
		throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
	}

	shared_ptr<Ciphertext<Element>> newCiphertext( new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	Element c1(ciphertext1->GetElement());

	Element c2(ciphertext2->GetElement());

	Element cResult = c1*c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;		}

/**
 * Function for evaluating multiplication on ciphertext followed by key switching operation.
 *
 * @param &ciphertext1 first input ciphertext.
 * @param &ciphertext2 second input ciphertext.
 * @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
 * @param *newCiphertext the new resulting ciphertext.
 */
template <class Element>
shared_ptr<Ciphertext<Element>>
LPAlgorithmSHENull<Element>::EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const
		{
	if(ciphertext1->GetElement().GetFormat() == Format::COEFFICIENT || ciphertext2->GetElement().GetFormat() == Format::COEFFICIENT){
		throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
	}

	shared_ptr<Ciphertext<Element>> newCiphertext( new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

	Element c1(ciphertext1->GetElement());

	Element c2(ciphertext2->GetElement());

	Element cResult = c1*c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;}

/**
 * Function for evaluation addition on ciphertext.
 *
 * @param &ciphertext1 first input ciphertext.
 * @param &ciphertext2 second input ciphertext.
 * @param *newCiphertext the new resulting ciphertext.
 */

template <class Element>
shared_ptr<Ciphertext<Element>>
LPAlgorithmSHENull<Element>::EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const
		{
	shared_ptr<Ciphertext<Element>> newCiphertext( new Ciphertext<Element>( ciphertext1->GetCryptoContext() ) );

	Element c1(ciphertext1->GetElement());
	Element c2(ciphertext2->GetElement());

	Element cResult = c1+c2;

	newCiphertext->SetElement(cResult);

	return newCiphertext;
		}


// Constructor for LPPublicKeyEncryptionSchemeNull
template <class Element>
LPPublicKeyEncryptionSchemeNull<Element>::LPPublicKeyEncryptionSchemeNull(std::bitset<FEATURESETSIZE> mask)
: LPPublicKeyEncryptionScheme<Element>() {

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmNull<Element>(*this);

	if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPRENull<Element>(*this);
	//	if (mask[EVALADD])
	//		this->m_algorithmEvalAdd = new LPAlgorithmAHENull<Element>(*this);
	//	if (mask[EVALAUTOMORPHISM])
	//		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphNull<Element>(*this);
	if (mask[SHE])
		this->m_algorithmSHE = new LPAlgorithmSHENull<Element>(*this);
	//	if (mask[FHE])
	//		this->m_algorithmFHE = new LPAlgorithmFHENull<Element>(*this);
	//	if (mask[LEVELEDSHE])
	//		this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmNull<Element>(*this);
}

// Enable for LPPublicKeyEncryptionSchemeLTV
template <class Element>
void LPPublicKeyEncryptionSchemeNull<Element>::Enable(PKESchemeFeature feature) {
	switch (feature)
	{
	case ENCRYPTION:
		if (this->m_algorithmEncryption == NULL)
			this->m_algorithmEncryption = new LPAlgorithmNull<Element>(*this);
		break;
	case PRE:
		if (this->m_algorithmPRE == NULL)
			this->m_algorithmPRE = new LPAlgorithmPRENull<Element>(*this);
		break;
		//	case EVALADD:
		//		if (this->m_algorithmEvalAdd == NULL)
		//			this->m_algorithmEvalAdd = new LPAlgorithmAHENull<Element>(*this);
		//		break;
		//	case EVALAUTOMORPHISM:
		//		if (this->m_algorithmEvalAutomorphism == NULL)
		//			this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphNull<Element>(*this);
		//		break;
	case SHE:
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHENull<Element>(*this);
		break;
		//	case FHE:
		//		if (this->m_algorithmFHE == NULL)
		//			this->m_algorithmFHE = new LPAlgorithmFHENull<Element>(*this);
		//		break;
		//	case LEVELEDSHE:
		//		if (this->m_algorithmLeveledSHE == NULL)
		//			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmNull<Element>(*this);
		//		break;
	}
}

}
