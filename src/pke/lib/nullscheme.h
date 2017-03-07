/*
 * nullscheme.h
 *
 *  Created on: Oct 4, 2016
 *      Author: gwryan
 */

#ifndef SRC_LIB_CRYPTO_NULLSCHEME_H_
#define SRC_LIB_CRYPTO_NULLSCHEME_H_

#include "palisade.h"

namespace lbcrypto {

template <class Element>
class LPCryptoParametersNull : public LPCryptoParameters<Element> {
private:
	DiscreteGaussianGenerator	m_dgg;

public:
	LPCryptoParametersNull() : LPCryptoParameters<Element>() {}

	LPCryptoParametersNull(const shared_ptr<typename Element::Params> ep, const BigBinaryInteger &plaintextModulus)
		: LPCryptoParameters<Element>(ep, plaintextModulus) {}

	LPCryptoParametersNull(const LPCryptoParametersNull& rhs) : LPCryptoParameters<Element>(rhs) {}

	virtual ~LPCryptoParametersNull() {}

	const DiscreteGaussianGenerator &GetDiscreteGaussianGenerator() const {return m_dgg;}

	virtual void SetPlaintextModulus(const BigBinaryInteger &plaintextModulus) {
		LPCryptoParameters<Element>::SetPlaintextModulus(plaintextModulus);
		std::dynamic_pointer_cast<ILParams>(this->GetElementParams())->SetModulus( plaintextModulus );
	}

	bool Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);

		Serialized pser(rapidjson::kObjectType, &serObj->GetAllocator());

		if( !this->GetElementParams()->Serialize(&pser) )
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

		typename Element::Params *json_ilParams = new typename Element::Params();

		if( !json_ilParams->Deserialize(oneItem) ) {
			delete json_ilParams;
			return false;
		}

		this->SetElementParams( shared_ptr<typename Element::Params>(json_ilParams) );

		if( (pIt = mIter->value.FindMember("PlaintextModulus")) == mIter->value.MemberEnd() )
			return false;
		BigBinaryInteger bbiPlaintextModulus(pIt->value.GetString());

		this->SetPlaintextModulus(bbiPlaintextModulus);
		return true;
	}


	/**
	* == operator to compare to this instance of LPCryptoParametersNull object.
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
class LPAlgorithmNull : public LPEncryptionAlgorithm<Element> {
public:
	/**
	 * Default constructor
	 */
	LPAlgorithmNull() {}

	/**
	* Method for encrypting plaintext using Null
	*
	* @param &publicKey public key used for encryption.
	* @param &plaintext the plaintext input.
	* @param *ciphertext ciphertext which results from encryption.
	*/
	shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> pubKey,
		Element &plaintext) const {
		shared_ptr<Ciphertext<Element>> ciphertext( new Ciphertext<Element>(pubKey->GetCryptoContext()) );

		Element copyPlain(pubKey->GetCryptoContext().GetCryptoParameters()->GetElementParams());
		copyPlain.SetValues(plaintext.GetValues(), Format::EVALUATION);

		ciphertext->SetElement(copyPlain);

		return ciphertext;
	}

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
		Element *plaintext) const {
		*plaintext = ciphertext->GetElement();
		return DecryptResult(plaintext->GetLength());
	}

	/**
	* Function to generate public and private keys
	*
	* @param &publicKey private key used for decryption.
	* @param &privateKey private key used for decryption.
	* @return function ran correctly.
	*/
	virtual LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse=false) const {
		LPKeyPair<Element>	kp( new LPPublicKey<Element>(cc), new LPPrivateKey<Element>(cc) );

		Element a(cc.GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);
		kp.secretKey->SetPrivateElement(a);
		kp.publicKey->SetPublicElementAtIndex(0, a);
		kp.publicKey->SetPublicElementAtIndex(1, a);

		return kp;
	}

};

/**
* @brief PRE scheme based on Null.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmPRENull : public LPPREAlgorithm<Element> {
public:
	/**
	 * Default constructor
	 */
	LPAlgorithmPRENull() {}

	/**
	* Function to generate 1..log(q) encryptions for each bit of the original private key
	* Variant that uses the public key for the new secret key.
	*
	* @param &newPrivateKey encryption key for the new ciphertext.
	* @param &origPrivateKey original private key used for decryption.
	* @param &ddg discrete Gaussian generator.
	* @param *evalKey the evaluation key.
	*/
	shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPublicKey<Element>> newPrivateKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
		// create a new ReKey of the proper type, in this context
		shared_ptr<LPEvalKeyNTRURelin<Element>> EK( new LPEvalKeyNTRURelin<Element>(newPrivateKey->GetCryptoContext()) );

		Element a(newPrivateKey->GetCryptoContext().GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);
		vector<Element> evalKeyElements;
		evalKeyElements.push_back(std::move(a));

		EK->SetAVector(std::move(evalKeyElements));

		return EK;
	}

	/**
	* Function to generate 1..log(q) encryptions for each bit of the original private key
	* Variant that uses the new secret key directly.
	*
	* @param &newPrivateKey encryption key for the new ciphertext.
	* @param &origPrivateKey original private key used for decryption.
	* @param &ddg discrete Gaussian generator.
	* @param *evalKey the evaluation key.
	*/
	shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newPrivateKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
		// create a new ReKey of the proper type, in this context
		shared_ptr<LPEvalKeyNTRURelin<Element>> EK(new LPEvalKeyNTRURelin<Element>(newPrivateKey->GetCryptoContext()));

		Element a(newPrivateKey->GetCryptoContext().GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);
		vector<Element> evalKeyElements;
		evalKeyElements.push_back(std::move(a));

		EK->SetAVector(std::move(evalKeyElements));

		return EK;
	}

	/**
	* Function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
	*
	* @param &evalKey the evaluation key.
	* @param &ciphertext the input ciphertext.
	* @param *newCiphertext the new ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const {
		shared_ptr<Ciphertext<Element>> newCiphertext( new Ciphertext<Element>(*ciphertext) );
		return newCiphertext;
	}

};

/**
 * @brief Concrete feature class for Leveled SHELTV operations
 * @tparam Element a ring element.
 */
template <class Element>
class LPLeveledSHEAlgorithmNull : public LPLeveledSHEAlgorithm<Element> { // FIXME: not implemented!
	public:
		/**
		* Default constructor
		*/
		LPLeveledSHEAlgorithmNull() {}

		/**
		 * Method for ModReducing CipherText and the Private Key used for encryption.
		 *
		 * @param *cipherText Ciphertext to perform and apply modreduce on.
		 */
		shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const;
		/**
		 * Method for RingReducing CipherText and the Private Key used for encryption.
		 *
		 * @param *cipherText Ciphertext to perform and apply ringreduce on.
		 * @param *keySwitchHint is the keyswitchhint from the ciphertext's private key to a sparse key
		 */
		shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const ;

		/**
		* Method for ComposedEvalMult
		*
		* @param &cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
		* @param &cipherText2 cipherText2, second input ciphertext to perform multiplication on.
		* @param &quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
		* @param &cipherTextResult is the resulting ciphertext that can be decrypted with the secret key of the particular level.
		*/
		shared_ptr<Ciphertext<Element>> ComposedEvalMult(
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
		shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
				const shared_ptr<LPEvalKeyNTRU<Element>> linearKeySwitchHint) const ;

		/**
		* Function that determines if security requirements are met if ring dimension is reduced by half.
		*
		* @param ringDimension is the original ringDimension
		* @param &moduli is the vector of moduli that is used
		* @param rootHermiteFactor is the security threshold
		*/
		bool CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const;
};

template <class Element>
class LPAlgorithmSHENull : public LPSHEAlgorithm<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmSHENull() {}

		/**
		* Function for evaluation addition on ciphertext.
		*
		* @param &ciphertext1 first input ciphertext.
		* @param &ciphertext2 second input ciphertext.
		* @param *newCiphertext the new resulting ciphertext.
		*/

		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const {
			shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

			const Element& c1 = ciphertext1->GetElement();
			const Element& c2 = ciphertext2->GetElement();

			Element cResult = c1 + c2;

			newCiphertext->SetElement(std::move(cResult));

			return newCiphertext;
		}


		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const {
			shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext1->GetCryptoContext()));

			const Element& c1 = ciphertext1->GetElement();
			const Element& c2 = ciphertext2->GetElement();

			Element cResult = c1 - c2;

			newCiphertext->SetElement(std::move(cResult));

			return newCiphertext;
		}


		/**
		 * Function for evaluating multiplication on ciphertext.
		 *
		 * @param &ciphertext1 first input ciphertext.
		 * @param &ciphertext2 second input ciphertext.
		 * @param *newCiphertext the new resulting ciphertext.
		 */
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const {
			if (typeid(Element) != typeid(ILVector2n)) {
				throw std::runtime_error("EvalMult only implemented for Null Scheme and element ILVector2n.");
			}

			if (ciphertext1->GetElement().GetFormat() == Format::COEFFICIENT || ciphertext2->GetElement().GetFormat() == Format::COEFFICIENT) {
				throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
			}

			shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext2->GetCryptoContext()));

			const Element& c1 = ciphertext1->GetElement();
			const Element& c2 = ciphertext2->GetElement();

			Element cResult(ciphertext1->GetCryptoContext().GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);

			Element cLarger(ciphertext1->GetCryptoContext().GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);

			const BigBinaryInteger& ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();
			int	ringdim = c1.GetCyclotomicOrder() / 2;

			for (int c1e = 0; c1e<ringdim; c1e++) {
				BigBinaryInteger answer, c1val, c2val, prod;
				c1val = c1.GetValAtIndex(c1e);
				if (c1val != BigBinaryInteger::ZERO) {
					for (int c2e = 0; c2e<ringdim; c2e++) {
						c2val = c2.GetValAtIndex(c2e);
						if (c2val != BigBinaryInteger::ZERO) {
							prod = c1val * c2val;

							int index = (c1e + c2e);

							if (index >= ringdim) {
								index %= ringdim;
								cLarger.SetValAtIndex(index, (cLarger.GetValAtIndex(index) + prod) % ptm);
							}
							else
								cResult.SetValAtIndex(index, (cResult.GetValAtIndex(index) + prod) % ptm);
						}
					}
				}
			}

			// fold cLarger back into the answer
			for (int i = 0; i<ringdim; i++) {
				BigBinaryInteger adj;
				adj = cResult.GetValAtIndex(i) + (ptm - cLarger.GetValAtIndex(i)) % ptm;
				cResult.SetValAtIndex(i, adj % ptm);
			}

			// DO NOT USE element's operator* !!!  Element cResult = c1*c2;

			newCiphertext->SetElement(cResult);

			return newCiphertext;
		}

		/**
		* Function for evaluating multiplication on ciphertext followed by key switching operation.
		*
		* @param &ciphertext1 first input ciphertext.
		* @param &ciphertext2 second input ciphertext.
		* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
		* @param *newCiphertext the new resulting ciphertext.
		*/
		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
				const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const {

			return EvalMult(ciphertext1, ciphertext2);
		}

		/**
		* Function for homomorpic negation of ciphertext.
		*
		* @param &ciphertext input ciphertext.
		* @param *newCiphertext the new resulting ciphertext.
		*/

		shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const {
			shared_ptr<Ciphertext<Element>> newCiphertext(new Ciphertext<Element>(ciphertext->GetCryptoContext()));

			const Element& c1 = ciphertext->GetElement();

			Element cResult = c1.Negate();

			newCiphertext->SetElement(std::move(cResult));

			return newCiphertext;
		}


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
		* Method for KeySwitching based on RLWE relinearization.
		* Function to generate 1..log(q) encryptions for each bit of the original private key
		*
		* @param &newPublicKey encryption key for the new ciphertext.
		* @param origPrivateKey original private key used for decryption.
		*/
		shared_ptr<LPEvalKey<Element>> KeySwitchRelinGen(const shared_ptr<LPPublicKey<Element>> newPublicKey,
			const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
			return shared_ptr<LPEvalKey<Element>>();
		}

		/**
		* Method for KeySwitching based on RLWE relinearization
		*
		* @param evalKey the evaluation key.
		* @param ciphertext the input ciphertext.
		* @return the resulting Ciphertext
		*/
		shared_ptr<Ciphertext<Element>> KeySwitchRelin(const shared_ptr<LPEvalKey<Element>> evalKey,
			const shared_ptr<Ciphertext<Element>> ciphertext) const {
			shared_ptr<Ciphertext<Element>> ans(new Ciphertext<Element>());
			return ans;
		}

		/**
		 * Function to generate key switch hint on a ciphertext for depth 2.
		 *
		 * @param &newPrivateKey private key for the new ciphertext.
		 * @param *keySwitchHint the key switch hint.
		 */
		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const {
			shared_ptr<LPEvalKey<Element>> EK( new LPEvalKeyRelin<Element>(originalPrivateKey->GetCryptoContext()) );

			Element a(originalPrivateKey->GetCryptoContext().GetCryptoParameters()->GetElementParams(), Format::EVALUATION, true);
			vector<Element> evalKeyElements;
			evalKeyElements.push_back(std::move(a));

			EK->SetAVector(std::move(evalKeyElements));

			return EK;
		}


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
* @brief Parameter generation for FV.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmParamsGenNull : public LPParameterGenerationAlgorithm<Element> {
public:

	/**
	 * Default constructor
	 */
	LPAlgorithmParamsGenNull() {}

	/**
	* Method for computing all derived parameters based on chosen primitive parameters
	*
	* @param cryptoParams the crypto parameters object to be populated with parameters.
	* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
	* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
	* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
	*/
	bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
		int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const {
		return true;
	}

};


/**
* @brief Main public key encryption scheme for Null implementation,
* @tparam Element a ring element.
*/
template <class Element>
class LPPublicKeyEncryptionSchemeNull : public LPPublicKeyEncryptionScheme<Element> {
public:
	LPPublicKeyEncryptionSchemeNull() : LPPublicKeyEncryptionScheme<Element>() {
		this->m_algorithmParamsGen = new LPAlgorithmParamsGenNull<Element>();
	}

	LPPublicKeyEncryptionSchemeNull(std::bitset<FEATURESETSIZE> mask) {

		if (mask[ENCRYPTION])
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmNull<Element>();

		if (mask[PRE])
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE = new LPAlgorithmPRENull<Element>();

		if (mask[SHE])
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHENull<Element>();

		//	if (mask[FHE])
		//		this->m_algorithmFHE = new LPAlgorithmFHENull<Element>();
		//	if (mask[LEVELEDSHE])
		//		this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmNull<Element>();
	}

	void Enable(PKESchemeFeature feature) {
		switch (feature)
		{
		case ENCRYPTION:
			if (this->m_algorithmEncryption == NULL)
				this->m_algorithmEncryption = new LPAlgorithmNull<Element>();
			break;
		case PRE:
			if (this->m_algorithmPRE == NULL)
				this->m_algorithmPRE = new LPAlgorithmPRENull<Element>();
			break;
		case SHE:
			if (this->m_algorithmSHE == NULL)
				this->m_algorithmSHE = new LPAlgorithmSHENull<Element>();
			break;
			//	case FHE:
			//		if (this->m_algorithmFHE == NULL)
			//			this->m_algorithmFHE = new LPAlgorithmFHENull<Element>();
			//		break;
			//	case LEVELEDSHE:
			//		if (this->m_algorithmLeveledSHE == NULL)
			//			this->m_algorithmLeveledSHE = new LPLeveledSHEAlgorithmNull<Element>();
			//		break;
		}
	}
};


}

#endif /* SRC_LIB_CRYPTO_NULLSCHEME_H_ */
