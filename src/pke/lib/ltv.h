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
 * This code provides the definitions for the LTV scheme
 */

#ifndef LBCRYPTO_CRYPTO_LTV_H
#define LBCRYPTO_CRYPTO_LTV_H

#include "palisade.h"

namespace lbcrypto {

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class LPCryptoParametersLTV: public LPCryptoParametersRLWE<Element> {
public:

	/**
	 * Default constructor
	 */
	LPCryptoParametersLTV() : LPCryptoParametersRLWE<Element>() {}

	/**
	 * Copy constructor.
	 * @param rhs - source
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
			shared_ptr<typename Element::Params> params,
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

	/**
	 * Serialize the LTV Crypto Parameters
	 *
	 * @param serObj - rapidJson object for the serializaion
	 * @return true on success
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
	 * Deserialize the LTV Crypto Parameters
	 *
	 * @param serObj
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj) {
		Serialized::ConstMemberIterator mIter = serObj.FindMember("LPCryptoParametersLTV");
		if( mIter == serObj.MemberEnd() ) return false;

		return this->DeserializeRLWE(mIter);
	}

	/**
	 * ParameterSelection for LTV Crypto Parameters
	 * FIXME this will be replaced by the new mechanism for crypto params
	 * @param cryptoParams
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
	// FIXME this goes away
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
	// FIXME this goes away
	void ParameterSelection(usint& n, vector<BigBinaryInteger> &moduli);
};

/**
* @brief Encryption algorithm implementation template for Ring-LWE NTRU-based schemes,
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmLTV : public LPEncryptionAlgorithm<Element> {
public:

	/**
	 * Default Constructor
	 */
	LPAlgorithmLTV() {}

	/**
	 * Encrypt method for LTV Scheme
	 *
	 * @param publicKey - the encryption key
	 * @param plaintext - plaintext to be encrypted
	 * @return a shared pointer to the encrypted Cyphertext
	 */
	shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey, Element &plaintext) const;

	/**
	 * Decrypt method for LTV Scheme
	 *
	 * @param privateKey - decryption key
	 * @param ciphertext - Ciphertext to be decrypted
	 * @param plaintext - Plaintext result of Decrypt operation
	 * @return DecryptResult indicating success or failure and number of bytes decrypted
	 */
	DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		Element *plaintext) const;

	/**
	 * KeyGen
	 * Note that in "sparse" mode, all even indices are non-zero
	 * and odd indices are set to zero.
	 *
	 * @param cc - crypto context in which to generate a key pair
	 * @param makeSparse - true to generate a sparse key pair
	 * @return public and private key pair
	 */
	LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse = false) const;
};

/**
* @brief Template for crypto PRE.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmPRELTV : public LPPREAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmPRELTV() {}

	/**
	* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
	* Variant that uses the new secret key directly.
	*
	* @param newKey new private key for the new ciphertext.
	* @param origPrivateKey original private key used for decryption.
	* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
	*/
	shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPrivateKey<Element>> newKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const {
		std::string errMsg = "LPAlgorithmPRELTV::ReKeyGen using the new secret key is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Function to generate a re-encryption key as 1..log(q) encryptions for each bit of the original private key
	* Variant that uses the public key for the new secret key.
	*
	* @param newKey public key for the new private key.
	* @param origPrivateKey original private key used for decryption.
	* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
	*/
	shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPublicKey<Element>> newKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

	/**
	* Function to define ciphertext re-encryption using the array generated by ReKeyGen
	*
	* @param evalKey the evaluation key.
	* @param ciphertext the input ciphertext.
	* @return the resulting Ciphertext
	*/
	shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const;
};

/**
* Evaluation multiplication for homomorphic encryption operations.
*
* @brief Template for crypto PRE.
* @tparam Element a ring element.
*/
template <class Element>
class LPAlgorithmSHELTV : public LPSHEAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmSHELTV() {}

	/**
	* Function for homomorphic addition of ciphertexts.
	*
	* @param ciphertext1 first input ciphertext.
	* @param ciphertext2 second input ciphertext.
	* @return resulting ciphertext.
	*/

	shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function for homomorphic subtraction of ciphertexts.
	*
	* @param ciphertext1 the input ciphertext.
	* @param ciphertext2 the input ciphertext.
	* @return resulting EvalSub ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function for homomorphic multiplication of ciphertexts without key switching.
	*
	* @param ciphertext1 first input ciphertext.
	* @param ciphertext2 second input ciphertext.
	* @return resulting EvalMult ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function for evaluating multiplication on ciphertexts with key switching.
	*
	* @param ciphertext1 first input ciphertext.
	* @param ciphertext2 second input ciphertext.
	* @return resulting EvalMult ciphertext with proper
	*/
	shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2,
		const shared_ptr<LPEvalKey<Element>> evalKey) const;

	/**
	* Function for homomorphic negation of ciphertexts.
	*
	* @param ct first input ciphertext.
	* @return new ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ct) const;
														 
	/**
	* Method for generating a KeySwitchHint (uses the NTRU method)
	*
	* @param &k1 Original private key used for encryption.
	* @param &k2 New private key to generate the keyswitch hint.
    * @result keyswitchhint.
	*/
	shared_ptr<LPEvalKey<Element>> KeySwitchGen(
		const shared_ptr<LPPrivateKey<Element>> k1,
		const shared_ptr<LPPrivateKey<Element>> k2) const;

	/**
	* Method for KeySwitching based on a KeySwitchHint (uses the NTRU method)
	*
	* @param keySwitchHint Hint required to perform the ciphertext switching.
	* @param cipherText Original ciphertext to perform switching on.
	* @result the resulting ciphertext
	*/
	shared_ptr<Ciphertext<Element>> KeySwitch(
		const shared_ptr<LPEvalKey<Element>> keySwitchHint,
		const shared_ptr<Ciphertext<Element>> cipherText) const;

	/**
	* Method for KeySwitching based on RLWE relinearization.
	* Function to generate 1..log(q) encryptions for each bit of the original private key
	*
	* @param &newPublicKey encryption key for the new ciphertext.
	* @param origPrivateKey original private key used for decryption.
	*/
	shared_ptr<LPEvalKey<Element>> KeySwitchRelinGen(const shared_ptr<LPPublicKey<Element>> newPublicKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

	/**
	* Method for KeySwitching based on RLWE relinearization
	*
	* @param evalKey the evaluation key.
	* @param ciphertext the input ciphertext.
	* @return the resulting Ciphertext
	*/
	shared_ptr<Ciphertext<Element>> KeySwitchRelin(const shared_ptr<LPEvalKey<Element>> evalKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const;

	/**
	* Function to generate key switch hint on a ciphertext for depth 2 (uses the NTRU method).
	*
	* @param &newPrivateKey private key for the new ciphertext.
	* @param *keySwitchHint the key switch hint.
	* @return resulting evalkeyswitch hint
	*/
	shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const;

	/**
	* Function for evaluating ciphertext at an index; works only with odd indices in the ciphertext.
	* The plaintext should be padded with zeros at even indices for this to work correctly. In other words,
	* if the ring dimension n is used, up to n/2 coefficients at odd indices can be encrypted.
	*
	* @param ciphertext the input ciphertext.
	* @param i index of the item to be "extracted", starts with 2.
	* @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
	*/
	shared_ptr<Ciphertext<Element>> EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext, const usint i,
		const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const;

	/**
	* Generate automophism keys for a given private key; works only with odd indices in the ciphertext (uses the RLWE relinerarization method)
	*
	* @param &publicKey original public key.
	* @param &origPrivateKey original private key.
	* @param size number of automorphims to be computed; starting from plaintext index 2; maximum is n/2-1
	* @param *tempPrivateKey used to store permutations of private key; passed as pointer because instances of LPPrivateKey cannot be created within the method itself
	* @param *evalKeys the evaluation keys; index 0 of the vector corresponds to plaintext index 2, index 1 to plaintex index 3, etc.
	*/
	bool EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey,
		const usint size, shared_ptr<LPPrivateKey<Element>> *tempPrivateKey,
		std::vector<shared_ptr<LPEvalKey<Element>>> *evalKeys) const;
};


/**
* @brief Concrete feature class for Leveled SHELTV operations
* @tparam Element a ring element.
*/
template <class Element>
class LPLeveledSHEAlgorithmLTV : public LPLeveledSHEAlgorithm<Element> {
public:
	/**
	* Default constructor
	*/
	LPLeveledSHEAlgorithmLTV() {}

	/**
	* Method for ModReducing CipherText
	*
	* @param cipherText Ciphertext to perform and apply modreduce on.
	* @return resulting modreduced ciphertext
	*/
	shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const;

	/**
	* Method for RingReducing CipherText and the Private Key used for encryption.
	*
	* @param cipherText Ciphertext to perform and apply ringreduce on.
	* @param keySwitchHint is the keyswitchhint from the ciphertext's private key to a sparse key
	* @return resulting RingReduced ciphertext
	*/
	shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const;

	/**
	* Method for ComposedEvalMult
	*
	* @param cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
	* @param cipherText2 cipherText2, second input ciphertext to perform multiplication on.
	* @param quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
	* @return the resulting ciphertext that can be decrypted with the secret key of the particular level.
	*/
	shared_ptr<Ciphertext<Element>> ComposedEvalMult(
		const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<Ciphertext<Element>> cipherText2,
		const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const;

	/**
	* Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
	*
	* @param cipherText1 is the original ciphertext to be key switched and mod reduced.
	* @param linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
	* @return the resulting ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const;

	/**
	* Function that determines if security requirements are met if ring dimension is reduced by half.
	*
	* @param ringDimension is the original ringDimension
	* @param &moduli is the vector of moduli that is used
	* @param rootHermiteFactor is the security threshold
	*/
	bool CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const;
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
	
	/**
	* Function to enable a scheme
	*
	*@param feature is the feature to enable
	*/
	void Enable(PKESchemeFeature feature);
};

}

#endif
