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

	bool Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);

		Serialized pser(rapidjson::kObjectType, &serObj->GetAllocator());
		const ElemParams& ep = *this->GetElementParams();
		if( !ep.Serialize(&pser) )
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
 * @brief Concrete feature class for Leveled SHELTV operations
 * @tparam Element a ring element.
 */
template <class Element>
class LPLeveledSHEAlgorithmNull : public LPLeveledSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
	public:
		/**
		* Default constructor
		*/
		LPLeveledSHEAlgorithmNull() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
		/**
		* Constructor that initliazes the scheme
		*
		* @param &scheme is a reference to scheme
		*/
		LPLeveledSHEAlgorithmNull(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

		/**
		 * Method for ModReducing CipherText and the Private Key used for encryption.
		 *
		 * @param *cipherText Ciphertext to perform and apply modreduce on.
		 */
		virtual shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const;
		/**
		 * Method for RingReducing CipherText and the Private Key used for encryption.
		 *
		 * @param *cipherText Ciphertext to perform and apply ringreduce on.
		 * @param *keySwitchHint is the keyswitchhint from the ciphertext's private key to a sparse key
		 */
		virtual shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const ;

		/**
		* Method for ComposedEvalMult
		*
		* @param &cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
		* @param &cipherText2 cipherText2, second input ciphertext to perform multiplication on.
		* @param &quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
		* @param &cipherTextResult is the resulting ciphertext that can be decrypted with the secret key of the particular level.
		*/
		virtual shared_ptr<Ciphertext<Element>> ComposedEvalMult(
				const shared_ptr<Ciphertext<Element>> cipherText1,
				const shared_ptr<Ciphertext<Element>> cipherText2,
				const shared_ptr<LPEvalKeyNTRU<Element>> quadKeySwitchHint) const ;

		/**
		* Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
		*
		* @param &cipherText1 is the original ciphertext to be key switched and mod reduced.
		* @param &linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
		* @param &cipherTextResult is the resulting ciphertext.
		*/
		virtual shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
				const shared_ptr<LPEvalKeyNTRU<Element>> linearKeySwitchHint) const ;
		/**
		* Function to generate sparse public and private keys. By sparse it is meant that all even indices are non-zero
		* and odd indices are set to zero.
		*
		* @param *publicKey is the public key to be generated.
		* @param *privateKey is the private key to be generated.
		*/
		virtual LPKeyPair<Element> SparseKeyGen(const CryptoContext<Element> cc) const;
		/**
		* Function that determines if security requirements are met if ring dimension is reduced by half.
		*
		* @param ringDimension is the original ringDimension
		* @param &moduli is the vector of moduli that is used
		* @param rootHermiteFactor is the security threshold
		*/
		virtual bool CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const;
};

template <class Element>
class LPAlgorithmSHENull : public LPSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmSHENull() : LPPublicKeyEncryptionAlgorithmImpl<Element>(){};
		/**
		* Constructor that initliazes the scheme
		*
		* @param &scheme is a reference to scheme
		*/
		LPAlgorithmSHENull(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

		/**
		* Function for evaluation addition on ciphertext.
		*
		* @param &ciphertext1 first input ciphertext.
		* @param &ciphertext2 second input ciphertext.
		* @param *newCiphertext the new resulting ciphertext.
		*/

		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		/**
		 * Function for evaluating multiplication on ciphertext.
		 *
		 * @param &ciphertext1 first input ciphertext.
		 * @param &ciphertext2 second input ciphertext.
		 * @param *newCiphertext the new resulting ciphertext.
		 */
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const;

		/**
		* Function for evaluating multiplication on ciphertext followed by key switching operation.
		*
		* @param &ciphertext1 first input ciphertext.
		* @param &ciphertext2 second input ciphertext.
		* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
				const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const;

		/**
		* Method for generating a KeySwitchHint
		*
		* @param &originalPrivateKey Original private key used for encryption.
		* @param &newPrivateKey New private key to generate the keyswitch hint.
		* @param *keySwitchHint is where the resulting keySwitchHint will be placed.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey, const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {
			return shared_ptr<LPEvalKey<Element>>();
		}

		/**
		* Function to define key switching operation
		*
		* @param &keySwitchHint the evaluation key.
		* @param &ciphertext the input ciphertext.
		* @param *newCiphertext the new ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> KeySwitch(
			const shared_ptr<LPEvalKey<Element>> keySwitchHint,
			const shared_ptr<Ciphertext<Element>> cipherText) const {
			shared_ptr<Ciphertext<Element>> ans(new Ciphertext<Element>());
			return ans;
		}



		/**
		 * Function to generate key switch hint on a ciphertext for depth 2.
		 *
		 * @param &newPrivateKey private key for the new ciphertext.
		 * @param *keySwitchHint the key switch hint.
		 */
		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const;

		/**
		 * Virtual function to define the interface for evaluating ciphertext at an index
		 *
		 * @param &ciphertext the input ciphertext.
		 * @param *newCiphertext the new ciphertext.
		 */
		shared_ptr<Ciphertext<Element>> EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext, const usint i,
				const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const {
			shared_ptr<Ciphertext<Element>> ans(new Ciphertext<Element>());
			return ans;
		}

		/**
		 * Virtual function to generate all isomorphism keys for a given private key
		 *
		 * @param &publicKey encryption key for the new ciphertext.
		 * @param &origPrivateKey original private key used for decryption.
		 * @param *evalKeys the evaluation keys.
		 * @return a vector of re-encryption keys.
		 */
		virtual bool EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey,
			const usint size, shared_ptr<LPPrivateKey<Element>> *tempPrivateKey,
			std::vector<shared_ptr<LPEvalKey<Element>>> *evalKeys) const {
			return false;
		}
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
