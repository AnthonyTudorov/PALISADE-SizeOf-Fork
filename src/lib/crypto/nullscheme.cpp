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

	std::vector<Element> evalKeyElements(1);
	std::vector<Element> evalKeyElementsGenerated;

	for (usint i = 0; i < (evalKeyElements.size()); i++)
	{
		// Generate a_i vectors
		Element a(newSK->GetCryptoContext().GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);
		evalKeyElementsGenerated.push_back(a);
	}

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

// Constructor for LPPublicKeyEncryptionSchemeNull
template <class Element>
LPPublicKeyEncryptionSchemeNull<Element>::LPPublicKeyEncryptionSchemeNull(std::bitset<FEATURESETSIZE> mask)
	: LPPublicKeyEncryptionScheme<Element>() {

	if (mask[ENCRYPTION])
		this->m_algorithmEncryption = new LPAlgorithmNull<Element>(*this);

	if (mask[PRE])
		this->m_algorithmPRE = new LPAlgorithmPRENull<Element>(*this);
	/*if (mask[EVALADD])
		this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
	if (mask[EVALAUTOMORPHISM])
		this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
	if (mask[SHE])
		this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
	if (mask[FHE])
		this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);
	if (mask[LEVELEDSHE])
		this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>(*this);
	*/

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
	/*case EVALADD:
		if (this->m_algorithmEvalAdd == NULL)
			this->m_algorithmEvalAdd = new LPAlgorithmAHELTV<Element>(*this);
		break;
	case EVALAUTOMORPHISM:
		if (this->m_algorithmEvalAutomorphism == NULL)
			this->m_algorithmEvalAutomorphism = new LPAlgorithmAutoMorphLTV<Element>(*this);
		break;
	case SHE:
		if (this->m_algorithmSHE == NULL)
			this->m_algorithmSHE = new LPAlgorithmSHELTV<Element>(*this);
		break;
	case FHE:
		if (this->m_algorithmFHE == NULL)
			this->m_algorithmFHE = new LPAlgorithmFHELTV<Element>(*this);
		break;
	case LEVELEDSHE:
		if (this->m_algorithmLeveledSHE == NULL)
			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmLTV<Element>(*this);
		break;
		*/
	}
}


}
