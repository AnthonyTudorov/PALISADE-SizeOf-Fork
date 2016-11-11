/**0
 * @file ltv.h -- definitions for LTV Crypto Params
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Nishanth Pasham <np386@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>, Jerry Ryan <gwryan@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 *
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 * This code provides the core proxy re-encryption functionality.
 */

#ifndef LBCRYPTO_CRYPTO_LTV_H
#define LBCRYPTO_CRYPTO_LTV_H

//#include "../crypto/rlwe.h"
#include "../palisade.h"

namespace lbcrypto {

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersLTV: public LPCryptoParametersRLWE<Element> {
public:

	/**
	 * Constructor that initializes all values to 0.
	 */
	LPCryptoParametersLTV() : LPCryptoParametersRLWE<Element>() {}

	/**
	 * Copy constructor.
	 *
	 */
	LPCryptoParametersLTV(const LPCryptoParametersLTV &rhs) : LPCryptoParametersRLWE<Element>(rhs) {}

	/**
	 * Constructor that initializes values.
	 *
	 * @param &params element parameters.
	 * @param &plaintextModulus plaintext modulus.
	 * @param distributionParameter noise distribution parameter.
	 * @param assuranceMeasure assurance level.
	 * @param securityLevel security level.
	 * @param relinWindow the size of the relinearization window.
	 * @param depth depth which is set to 1.
	 */
	LPCryptoParametersLTV(
			shared_ptr<ElemParams> params,
			const BigBinaryInteger &plaintextModulus,
			float distributionParameter,
			float assuranceMeasure,
			float securityLevel,
			usint relinWindow,
			int depth = 1)
	: LPCryptoParametersRLWE<Element>(
			params,
			plaintextModulus,
			distributionParameter,
			assuranceMeasure,
			securityLevel,
			relinWindow,
			depth) {}

	/**
	 * Destructor
	 */
	virtual ~LPCryptoParametersLTV() {}

	//JSON FACILITY
	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @param fileFlag is an object-specific parameter for the serialization
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const {
		if( !serObj->IsObject() )
			return false;

		SerialItem cryptoParamsMap(rapidjson::kObjectType);
		if( this->SerializeRLWE(serObj, cryptoParamsMap) == false )
			return false;

		serObj->AddMember("LPCryptoParametersLTV", cryptoParamsMap.Move(), serObj->GetAllocator());
		serObj->AddMember("LPCryptoParametersType", "LPCryptoParametersLTV", serObj->GetAllocator());

		return true;
	}

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersLTV");
		if( mIter == serObj.MemberEnd() ) return false;

		return this->DeserializeRLWE(mIter);
	}

	/**
	 * Creates a new set of parameters for LPCryptoParametersLTV amid a new ILDCRTParams. The new ILDCRTParams will allow for
	 * SHE operations of the existing depth. Note that the cyclotomic order also changes.
	 *
	 * @param *cryptoParams is where the resulting new LPCryptoParametersLTV will be placed in.
	 */
	void ParameterSelection(LPCryptoParametersLTV<ILVectorArray2n> *cryptoParams);

	/**
	 * == operator to compare to this instance of LPCryptoParametersLTV object.
	 *
	 * @param &rhs LPCryptoParameters to check equality against.
	 */
	bool operator==(const LPCryptoParameters<Element> &rhs) const {
		const LPCryptoParametersLTV<Element> *el = dynamic_cast<const LPCryptoParametersLTV<Element> *>(&rhs);

		if( el == 0 ) return false;
		return LPCryptoParametersRLWE<Element>::operator ==(rhs);
	}

private:

	//helper function for ParameterSelection. Splits the string 's' by the delimeter 'c'.
	std::string split(const std::string s, char c){
		std::string result;
		const char *str = s.c_str();
		const char *begin = str;
		while(*str != c && *str)
			str++;
		result = std::string(begin, str);
		return result;
	}

	//function for parameter selection. The public ParameterSelection function is a wrapper around this function.
	void ParameterSelection(usint& n, vector<BigBinaryInteger> &moduli);

};

/**
* @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmLTV : public LPEncryptionAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	/**
	* Default Constructor
	*/
	LPAlgorithmLTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	/**
	* Constructor that initliazes the scheme
	*
	*@param &scheme
	*/
	LPAlgorithmLTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Method for encrypting plaintext using Ring-LWE NTRU
	*
	* @param &publicKey public key used for encryption.
	* @param &plaintext the plaintext input.
	* @param *ciphertext ciphertext which results from encryption.
	* @return an instance of EncryptResult related to the ciphertext that is encrypted.
	*/
	shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey, Element &plaintext) const;

	/**
	* Method for decrypting plaintext using Ring-LWE NTRU
	*
	* @param &privateKey private key used for decryption.
	* @param &ciphertext ciphertext id decrypted.
	* @param *plaintext the plaintext output.
	* @return an instance of DecryptResult related to the plaintext that is decrypted
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
* @brief Template for crypto PRE.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmPRELTV : public LPPREAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmPRELTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	/**
	* Constructor that initliazes the scheme
	*
	* @param &scheme is a reference to scheme
	*/
	LPAlgorithmPRELTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Function to generate 1..log(q) encryptions for each bit of the original private key
	*
	* @param &newPublicKey encryption key for the new ciphertext.
	* @param &origPrivateKey original private key used for decryption.
	* @param *evalKey the evaluation key.
	*/
	shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPKey<Element>> newPublicKey,
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
* Evaluation addition for homomorphic encryption operations.
*
* @brief Template for crypto PRE.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmAHELTV : public LPAHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmAHELTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};

	/**
	* Constructor that initliazes the scheme
	*
	* @param &scheme is a reference to scheme
	*/
	LPAlgorithmAHELTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Virtual function to define the interface for evaluation addition on ciphertext.
	*
	* @param &ciphertext1 the input ciphertext.
	* @param &ciphertext2 the input ciphertext.
	* @param *newCiphertext the new ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

};

/**
* Automorphism-based SHE operations.
*
* @brief Template for crypto PRE.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmAutoMorphLTV : public LPAutoMorphAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	/**
	* Default Constructor
	*/
	LPAlgorithmAutoMorphLTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	/**
	* Constructor that initliazes the scheme
	*
	* @param &scheme is a reference to scheme
	*/
	LPAlgorithmAutoMorphLTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Function for evaluating ciphertext at an index; works only with odd indices in the ciphertext
	*
	* @param &ciphertext the input ciphertext.
	* @param i index of the item to be "extracted", starts with 2.
	* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
	* @param *newCiphertext the new ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext, const usint i,
		const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const;

	/**
	* Generate automophism keys for a given private key; works only with odd indices in the ciphertext
	*
	* @param &publicKey original public key.
	* @param &origPrivateKey original private key.
	* @param size number of automorphims to be computed; starting from plaintext index 2; maximum is m/2-1
	* @param *tempPrivateKey used to store permutations of private key; passed as pointer because instances of LPPrivateKey cannot be created within the method itself
	* @param *evalKeys the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
	*/
	virtual bool EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey,
		const usint size, shared_ptr<LPPrivateKey<Element>> *tempPrivateKey,
		std::vector<shared_ptr<LPEvalKey<Element>>> *evalKeys) const;

};

/**
* Evaluation multiplication for homomorphic encryption operations.
*
* @brief Template for crypto PRE.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmSHELTV : public LPSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmSHELTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	/**
	* Constructor that initliazes the scheme
	*
	* @param &scheme is a reference to scheme
	*/
	LPAlgorithmSHELTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Function for evaluating multiplication on ciphertext.
	*
	* @param &ciphertext1 first input ciphertext.
	* @param &ciphertext2 second input ciphertext.
	* @param *newCiphertext the new resulting ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2,
		const shared_ptr<LPEvalKey<Element>> evalKey) const;

	/**
	* Function for evaluation addition on ciphertext.
	*
	* @param &ciphertext1 first input ciphertext.
	* @param &ciphertext2 second input ciphertext.
	* @param *newCiphertext the new resulting ciphertext.
	*/

	shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function for homomorphic subtraction of ciphertexts.
	*
	* @param &ciphertext1 the input ciphertext.
	* @param &ciphertext2 the input ciphertext.
	* @param *newCiphertext the new ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function to generate key switch hint on a ciphertext for depth 2.
	*
	* @param &newPrivateKey private key for the new ciphertext.
	* @param *keySwitchHint the key switch hint.
	*/
	shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey) const;
};


/**
* @brief Concrete feature class for Leveled SHELTV operations
* @tparam Element a ring element.
*/
template <class Element>
class LPLeveledSHEAlgorithmLTV : public LPLeveledSHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:
	/**
	* Default constructor
	*/
	LPLeveledSHEAlgorithmLTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	/**
	* Constructor that initliazes the scheme
	*
	* @param &scheme is a reference to scheme
	*/
	LPLeveledSHEAlgorithmLTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Method for generating a KeySwitchHint
	*
	* @param &originalPrivateKey Original private key used for encryption.
	* @param &newPrivateKey New private key to generate the keyswitch hint.
	* @param *keySwitchHint is where the resulting keySwitchHint will be placed.
	*/
	virtual shared_ptr<LPEvalKey<Element>> KeySwitchGen(
		const shared_ptr<LPPrivateKey<Element>> k1,
		const shared_ptr<LPPrivateKey<Element>> k2) const;

	/**
	* Method for KeySwitching based on a KeySwitchHint
	*
	* @param &keySwitchHint Hint required to perform the ciphertext switching.
	* @param &cipherText Original ciphertext to perform switching on.
	*/
	virtual shared_ptr<Ciphertext<Element>> KeySwitch(
		const shared_ptr<LPEvalKey<Element>> keySwitchHint,
		const shared_ptr<Ciphertext<Element>> cipherText) const;

	/**
	* Method for generating a keyswitchhint from originalPrivateKey square to newPrivateKey
	*
	* @param &originalPrivateKey that is (in method) squared for the keyswitchhint.
	* @param &newPrivateKey new private for generating a keyswitchhint to.
	* @param *quadraticKeySwitchHint the generated keyswitchhint.
	*/
	virtual shared_ptr<LPEvalKey<Element>> QuadraticEvalMultKeyGen(
		const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
		const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const;

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
	virtual shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const;

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
		const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const;

	/**
	* Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
	*
	* @param &cipherText1 is the original ciphertext to be key switched and mod reduced.
	* @param &linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
	* @param &cipherTextResult is the resulting ciphertext.
	*/
	virtual shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const;
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

/**
* @brief Template for crypto PRE.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmFHELTV : public LPFHEAlgorithm<Element>, public LPPublicKeyEncryptionAlgorithmImpl<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmFHELTV() : LPPublicKeyEncryptionAlgorithmImpl<Element>() {};
	/**
	* Constructor that initliazes the scheme
	*
	* @param &scheme is a reference to scheme
	*/
	LPAlgorithmFHELTV(const LPPublicKeyEncryptionScheme<Element> &scheme) : LPPublicKeyEncryptionAlgorithmImpl<Element>(scheme) {};

	/**
	* Virtual function to define the interface for evaluation addition on ciphertext.
	*
	* @param &ciphertext the input ciphertext.
	* @param *newCiphertext the new ciphertext.
	*/
	void Bootstrap(const Ciphertext<Element> &ciphertext,
		Ciphertext<Element> *newCiphertext)  const;
};


/**
* @brief Main public key encryption scheme for LTV implementation,
* @tparam Element a ring element.
*/
template <class Element>
class LPPublicKeyEncryptionSchemeLTV : public LPPublicKeyEncryptionScheme<Element> {
public:
	/**
	* Inherited constructor
	*/
	LPPublicKeyEncryptionSchemeLTV() : LPPublicKeyEncryptionScheme<Element>() {}
	/**
	* Constructor that initalizes the mask
	*
	*@param mask the mask to be initialized
	*/
	LPPublicKeyEncryptionSchemeLTV(std::bitset<FEATURESETSIZE> mask);

	//These functions can be implemented later
	//Initialize(mask);
	/**
	* Function to enable a scheme
	*
	*@param feature is the feature to enable
	*/
	void Enable(PKESchemeFeature feature);
};

/**
* @brief placeholder for KeySwitchHints, both linear and quadratic, for Leveled SHE operations. Both linear and quadratic keys
* are stored in two separate vectors. The order in of keys in ascending order is the order of keys required for computation at each level
* of a leveled SHE operation.
* @tparam Element a ring element.
*/
template <class Element>
class LPLeveledSHEKeyStructure //: TODO: NISHANT to implement serializable public Serializable
{
private:
	std::vector< shared_ptr<LPEvalKey<Element>> > m_qksh;
	std::vector< shared_ptr<LPEvalKey<Element>> > m_lksh;
	usint m_levels;

public:
	/**
	*Constructor that initliazes the number of computation levels
	*
	* @param levels number of levels
	*/
	explicit LPLeveledSHEKeyStructure(usint levels) : m_levels(levels) { m_qksh.reserve(levels); m_lksh.reserve(levels); };

	/**
	*Get method for LinearKeySwitchHint for a particular level
	*
	*@return the LinearKeySwitchHint for the level
	*/
	const shared_ptr<LPEvalKey<Element>> GetLinearKeySwitchHintForLevel(usint level) const {
		if (level>m_levels - 1) {
			throw std::runtime_error("Level out of range");
		}
		else {
			return m_lksh[level];
		}
	};

	/**
	*Get method for QuadraticKeySwitchHint for a particular level
	*
	*@return the QuadraticKeySwitchHint for the level
	*/
	const shared_ptr<LPEvalKey<Element>> GetQuadraticKeySwitchHintForLevel(usint level) const {
		if (level>m_levels - 1) {
			throw std::runtime_error("Level out of range");
		}
		else {
			return m_qksh[level];
		}
	}
	/**
	* Method to add a LinearKeySwitchHint. The added key will be the key for the last level
	*
	*@param &lksh LinearKeySwitchHintLTV to be added.
	*/
	void PushBackLinearKey(const shared_ptr<LPEvalKey<Element>> lksh) {
		m_lksh.push_back(lksh);
	}
	/**
	* Method to add a QuadraticKeySwitchHint. The added key will be the key for the last level
	*
	*@param &quad QuadraticKeySwitchHintLTV to be added.
	*/
	void PushBackQuadraticKey(const shared_ptr<LPEvalKey<Element>> quad) {
		m_qksh.push_back(quad);
	}
	/**
	* Method to set LinearKeySwitchHint for a particular level of computation.
	*
	*@param &lksh LinearKeySwitchHintLTV to be set.
	*@param level is the level to set the key to.
	*/
	void SetLinearKeySwitchHintForLevel(const shared_ptr<LPEvalKey<Element>> lksh, usint level) {
		if (level>m_levels - 1) {
			throw std::runtime_error("Level out of range");
		}
		else {
			m_lksh[level] = lksh;
		}
	}
	/**
	* Method to set QuadraticKeySwitchHint for a particular level of computation.
	*
	*@param &qksh QuadraticKeySwitchHint to be set.
	*@param level is the level to set the key to.
	*/
	void SetQuadraticKeySwitchHintForLevel(const shared_ptr<LPEvalKey<Element>> qksh, usint level) {
		if (level>m_levels - 1)
		{
			throw std::runtime_error("Level out of range");
		}
		else {
			m_qksh[level] = qksh;
		}
	}
};



}

#endif
