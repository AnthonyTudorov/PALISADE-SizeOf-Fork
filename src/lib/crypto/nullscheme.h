/*
 * nullscheme.h
 *
 *  Created on: Oct 4, 2016
 *      Author: gwryan
 */

#ifndef SRC_LIB_CRYPTO_NULLSCHEME_H_
#define SRC_LIB_CRYPTO_NULLSCHEME_H_

#include "../palisade.h"

namespace lbcrypto {

template <class Element>
class LPCryptoParametersNull : public LPCryptoParameters<Element> {
public:
	LPCryptoParametersNull() : LPCryptoParameters<Element>() {}

	LPCryptoParametersNull(const shared_ptr<ElemParams> ep, const BigBinaryInteger &plaintextModulus)
		: LPCryptoParameters<Element>(ep, plaintextModulus) {}

	LPCryptoParametersNull(const LPCryptoParametersNull& rhs) : LPCryptoParameters<Element>(rhs) {}

	virtual ~LPCryptoParametersNull() {}

	bool Serialize(Serialized* serObj, const std::string fileFlag = "") const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);

		Serialized pser(rapidjson::kObjectType, &serObj->GetAllocator());
		const ElemParams& ep = *this->GetElementParams();
		if( !ep.Serialize(&pser, fileFlag) )
			return false;

		cryptoParamsMap.AddMember("ElemParams", pser.Move(), serObj->GetAllocator());
		cryptoParamsMap.AddMember("PlaintextModulus", this->GetPlaintextModulus().ToString(), serObj->GetAllocator());

		serObj->AddMember("LPCryptoParametersNull", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersNull", serObj->GetAllocator());

		return true;
	}

	/**
	* Populate the object from the deserialization of the Setialized
	* @param serObj contains the serialized object
	* @return true on success
	*/
	bool Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersNull");
		if( mIter == serObj.MemberEnd() ) return false;

		SerialItem::ConstMemberIterator pIt;

		if( (pIt = mIter->value.FindMember("ElemParams")) == mIter->value.MemberEnd() )
			return false;
		Serialized oneItem(rapidjson::kObjectType);
		SerialItem key( pIt->value.MemberBegin()->name, oneItem.GetAllocator() );
		SerialItem val( pIt->value.MemberBegin()->value, oneItem.GetAllocator() );
		oneItem.AddMember(key, val, oneItem.GetAllocator());

		ElemParams *json_ilParams;
		if( typeid(Element) == typeid(ILVector2n) )
			json_ilParams = new ILParams();
		else if( typeid(Element) == typeid(ILVectorArray2n) )
			json_ilParams = new ILDCRTParams();
		else {
			throw std::logic_error("Unrecognized element type");
		}

		if( !json_ilParams->Deserialize(oneItem) ) {
			delete json_ilParams;
			return false;
		}

		shared_ptr<ElemParams> ep( json_ilParams );
		this->SetElementParams( ep );

		if( (pIt = mIter->value.FindMember("PlaintextModulus")) == mIter->value.MemberEnd() )
			return false;
		BigBinaryInteger bbiPlaintextModulus(pIt->value.GetString());

		this->SetPlaintextModulus(bbiPlaintextModulus);
		return true;
	}


	/**
	* == operator to compare to this instance of LPCryptoParametersLTV object.
	*
	* @param &rhs LPCryptoParameters to check equality against.
	*/
	bool operator==(const LPCryptoParameters<Element> &rhs) const {
		const LPCryptoParametersNull<Element> *el = dynamic_cast<const LPCryptoParametersNull<Element> *>(&rhs);

		if( el == 0 ) return false;

		return true;
	}

};

template <class Element>
class LPAlgorithmNull : public LPEncryptionAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	//inherited constructors
	LPAlgorithmNull() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	LPAlgorithmNull(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Method for encrypting plaintext using Null
	*
	* @param &publicKey public key used for encryption.
	* @param &plaintext the plaintext input.
	* @param *ciphertext ciphertext which results from encryption.
	*/
	shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
		Element &plaintext) const;

	/**
	* Method for decrypting plaintext using Null
	*
	* @param &privateKey private key used for decryption.
	* @param &ciphertext ciphertext id decrypted.
	* @param *plaintext the plaintext output.
	* @return the decrypted plaintext returned.
	*/
	DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Element *plaintext) const;

	/**
	* Function to generate public and private keys
	*
	* @param &publicKey private key used for decryption.
	* @param &privateKey private key used for decryption.
	* @return function ran correctly.
	*/
	virtual LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc) const;

};

/**
* @brief PRE scheme based on Null.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmPRENull : public LPPREAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	//inherited constructors
	LPAlgorithmPRENull() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	LPAlgorithmPRENull(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Function to generate 1..log(q) encryptions for each bit of the original private key
	*
	* @param &newPrivateKey encryption key for the new ciphertext.
	* @param &origPrivateKey original private key used for decryption.
	* @param &ddg discrete Gaussian generator.
	* @param *evalKey the evaluation key.
	*/
	shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPKey<Element>> newPrivateKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

	/**
	* Function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
	*
	* @param &evalKey the evaluation key.
	* @param &ciphertext the input ciphertext.
	* @param *newCiphertext the new ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const;
};


/**
* @brief Main public key encryption scheme for Null implementation,
* @tparam Element a ring element.
*/
template <class Element>
class LPPublicKeyEncryptionSchemeNull : public LPPublicKeyEncryptionScheme<Element> {
public:
	LPPublicKeyEncryptionSchemeNull() : LPPublicKeyEncryptionScheme<Element>() {}
	LPPublicKeyEncryptionSchemeNull(std::bitset<FEATURESETSIZE> mask);

	void Enable(PKESchemeFeature feature);
};


}

#endif /* SRC_LIB_CRYPTO_NULLSCHEME_H_ */
