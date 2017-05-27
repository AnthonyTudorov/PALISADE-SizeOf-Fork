/**
 * @file ltv.h -- Operations for the LTV cryptoscheme.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * This code provides support for the LTV cryptoscheme.
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our design is informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
 *
 * Note that weaknesses have been discovered in this scheme and it should be used carefully.  Weaknesses come from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *   
 */

#ifndef LBCRYPTO_CRYPTO_LTV_H
#define LBCRYPTO_CRYPTO_LTV_H

#include "palisade.h"

namespace lbcrypto {

/**
 * @brief This is the parameters class for the LTV encryption scheme.  Note there have been recent advancements in the cryptanalysis of the LTV scheme, so parameters should be chosen with care.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 *  Parameters for this scheme are defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * @tparam Element a ring element type.
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
	 * Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
	 * infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
	 * chooses the basic noise, assurance and security parameters as the typical community-accepted values, 
	 * then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen 
	 * to provide correctness and security.  In some cases we would need to operate over already 
	 * encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
	 *
	 * @param &params Element parameters.  This will depend on the specific class of element being used.
	 * @param &plaintextModulus Plaintext modulus, typically denoted as p in most publications.
	 * @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
	 * @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
	 * @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes, although extra care is need for the LTV scheme because LTV makes an additional security assumption that make it suceptible to subfield lattice attacks.
	 * @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
	 * @param depth Depth is the depth of computation supprted which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
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
	* Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
	* infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
	* chooses the basic noise, assurance and security parameters as the typical community-accepted values,
	* then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen
	* to provide correctness and security.  In some cases we would need to operate over already
	* encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
	*
	* @param &params Element parameters.  This will depend on the specific class of element being used.
	* @param &encodingParams Plaintext space parameters.
	* @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
	* @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
	* @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes, although extra care is need for the LTV scheme because LTV makes an additional security assumption that make it suceptible to subfield lattice attacks.
	* @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
	* @param depth Depth is the depth of computation supprted which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
	*/
	LPCryptoParametersLTV(
		shared_ptr<typename Element::Params> params,
		shared_ptr<EncodingParams> encodingParams,
		float distributionParameter,
		float assuranceMeasure,
		float securityLevel,
		usint relinWindow,
		int depth = 1)
		: LPCryptoParametersRLWE<Element>(
			params,
			encodingParams,
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
	 * Serialize the LTV Crypto Parameters using rapidJson representation.
	 *
	 * @param serObj RapidJson object for the serializaion
	 * @return True on success
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
	 * Deserialize the LTV Crypto Parameters using rapidJson representation.
	 *
	 * @param serObj The serialized object to deserialize.
	 * @return True on success
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
	void ParameterSelection(LPCryptoParametersLTV<ILDCRT2n> *cryptoParams);

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

	void PrintParameters(std::ostream& os) const {
		LPCryptoParametersRLWE<Element>::PrintParameters(os);
	}

private:

	//helper function for ParameterSelection. Splits the string 's' by the delimeter 'c'.
	// FIXME This will soon be deprecated.
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
	// FIXME This will soon be deprecated.
	void ParameterSelection(usint& n, vector<native_int::BinaryInteger> &moduli);
};

/**
* @brief This is the algorithms class for the basic public key encrypt, decrypt and key generation methods for the LTV encryption scheme.  
 * Note there have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
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
	 * Encrypt method for the LTV Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param publicKey The encryption key.
	 * @param plaintext Plaintext to be encrypted.
	 * @return A shared pointer to the encrypted Ciphertext.
	 */
	shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey, ILVector2n &plaintext) const;

	/**
	 * Decrypt method for the LTV Scheme.  See the class description for citations on where the algorithms were
	 * taken from.
	 *
	 * @param privateKey Decryption key.
	 * @param ciphertext Diphertext to be decrypted.
	 * @param plaintext Plaintext result of Decrypt operation.
	 * @return DecryptResult indicating success or failure and number of bytes decrypted.
	 */
	DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext,
		ILVector2n *plaintext) const;

	/**
	 * Key Generation method for the LTV scheme.
	 * This method provides a "sparse" mode where all even indices are non-zero
	 * and odd indices are set to zero.  This sparse mode can be used to generate keys used for the LTV ring
	 * switching method.  We do not current support the generation of odd indices with even indices set to zero.
	 * See the class description for citations on where the algorithms were taken from.
	 *
	 * @param cc Drypto context in which to generate a key pair.
	 * @param makeSparse True to generate a sparse key pair.
	 * @return Public and private key pair.
	 */
	LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse = false) const;
};

/**
 * @brief This is the algorithms class for the Proxy Re-Encryption methods Re-Encryption Key Generation (ReKeyGen) and Re-Encryption (ReEncrypt) for the LTV encryption scheme.  
 * Note there have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This basic public key scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our PRE design and algorithms are informed by the design here:
 *   - Polyakov, Yuriy, Kurt Rohloff, Gyana Sahu and Vinod Vaikuntanathan. Fast Proxy Re-Encryption for Publish/Subscribe Systems. Under Review in ACM Transactions on Privacy and Security (ACM TOPS).
*
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
	* This variant that uses the new secret key directly along with the original secret key.
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
	* This variant that uses the new public key with the original secret key.
	*
	* @param newKey new private key for the new ciphertext.
	* @param origPrivateKey original private key used for decryption.
	* @return evalKey the evaluation key for switching the ciphertext to be decryptable by new private key.
	*/
	shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPPublicKey<Element>> newKey,
		const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const;

	/**
	* Function to define the interface for re-encypting ciphertext using the array generated by ProxyGen.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param evalKey the evaluation key.
	* @param ciphertext the input ciphertext.
	* @return A shared pointer to the resulting ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const;
	
};

	/**
	 * @brief The multiparty homomorphic encryption capability is not implemented for this scheme yet.
	 *
	 * @tparam Element a ring element.
	 */
template <class Element>
class LPAlgorithmMultipartyLTV : public LPMultipartyAlgorithm<Element> {
public:

	/**
	* Default constructor
	*/
	LPAlgorithmMultipartyLTV() {}

		/**
		* Function to generate public and private keys for multiparty homomrophic encryption in coordination with a leading client that generated a first public key.
		*
		* @param cc cryptocontext for the keys to be generated.
		* @param pk1 private key used for decryption to be fused.
		* @param makeSparse set to true if ring reduce by a factor of 2 is to be used.
		* @return key pair including the private and public key
		*/
	LPKeyPair<Element> MultipartyKeyGen(const CryptoContext<Element> cc,
		const shared_ptr<LPPublicKey<Element>> pk1,
		bool makeSparse=false) const {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyKeyGen using the new secret key is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}
	
		/**
		 * Method for main decryption operation run by most decryption clients for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
	LPKeyPair<Element> MultipartyKeyGen(const CryptoContext<Element> cc,
		const vector<shared_ptr<LPPrivateKey<Element>>>& secretKeys,
		bool makeSparse=false) const {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyKeyGen using the new secret key is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

		/**
		 * Method for decryption operation run by the lead decryption client for multiparty homomorphic encryption
		 *
		 * @param privateKey private key used for decryption.
		 * @param ciphertext ciphertext id decrypted.
		 */
	shared_ptr<Ciphertext<Element>> MultipartyDecryptMain(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyDecryptMain is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

		/**
		 * Method for fusing the partially decrypted ciphertext.
		 *
		 * @param &ciphertextVec ciphertext id decrypted.
		 * @param *plaintext the plaintext output.
		 * @return the decoding result.
		 */
	shared_ptr<Ciphertext<Element>> MultipartyDecryptLead(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const shared_ptr<Ciphertext<Element>> ciphertext) const {
		std::string errMsg = "LPAlgorithmPRELTV::MultipartyDecryptLead is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Method for decrypting plaintext using LTV
	*
	* @param &privateKey private key used for decryption.
	* @param &ciphertext1 ciphertext id decrypted.
	* @param &ciphertext2 ciphertext id decrypted.
	* @param *plaintext the plaintext output.
	* @return the success/fail result
	*/
	DecryptResult MultipartyDecryptFusion(const vector<shared_ptr<Ciphertext<Element>>>& ciphertextVec,
		ILVector2n *plaintext) const {
		std::string errMsg = "LPAlgorithmPREBV::MultipartyDecrypt is not implemented for the LTV Scheme.";
		throw std::runtime_error(errMsg);
	}
};

/**
* @brief This is the algorithms class for the Somewhat Homomorphic Encryption methods for the LTV encryption scheme.  These methods include the standard EvalAdd, EvalMult, EvalSub operations.
 * Note there have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
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
	* Function for evaluation addition on ciphertext.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
	*/
	shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function for homomorphic subtraction of ciphertexts.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @return A shared pointer to the ciphertext which is the EvalAdd of the two inputs.
	*/
	shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function for evaluating multiplication on ciphertext.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
	*/
	shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2) const;

	/**
	* Function for evaluating multiplication on ciphertext, but with a key switch performed after the
	* EvalMult using the Evaluation Key input.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ciphertext1 The first input ciphertext.
	* @param ciphertext2 The second input ciphertext.
	* @param evalKey The evaluation key input.
	* @return A shared pointer to the ciphertext which is the EvalMult of the two inputs.
	*/
	shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
		const shared_ptr<Ciphertext<Element>> ciphertext2,
		const shared_ptr<LPEvalKey<Element>> evalKey) const;

	/**
	* Function for homomorphic negation of ciphertexts.
	* At a high level, this operation substracts the plaintext value encrypted in the ciphertext from the
	* plaintext modulus p.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ct The input ciphertext.
	* @return A shared pointer to a new ciphertext which is the negation of the input.
	*/
	shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ct) const;
														 
	/**
	* Method for generating a Key Switch Hint.
	* See the class description for citations on where the algorithms were taken from.
	* This method generates a key switch hint which is not secure, even without the subfield lattice attacks.
	* We recommend that one uses key switch hints only for scenarios where security is not of critical 
	* importance.
	*
	* @param &k1 Original private key used for encryption.
	* @param &k2 New private key to generate the keyswitch hint.
	* @result A shared point to the resulting key switch hint.
	*/
	shared_ptr<LPEvalKey<Element>> KeySwitchGen(
		const shared_ptr<LPPrivateKey<Element>> k1,
		const shared_ptr<LPPrivateKey<Element>> k2) const;

	/**
	* Method for KeySwitching based on a KeySwitchHint.
	* See the class description for citations on where the algorithms were taken from.
	* This method uses a key switch hint which is not secure, even without the subfield lattice attacks.
	* We recommend that one uses key switch hints only for scenarios where security is not of critical 
	* importance.
	*
	* @param keySwitchHint Hint required to perform the ciphertext switching.
	* @param cipherText Original ciphertext to perform switching on.
	* @result A shared pointer to the resulting ciphertext.
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
	* Function to generate key switch hint on a ciphertext of depth 2.
	* This method uses a key switch hint which is not secure, even without the subfield lattice attacks.
	* We recommend that one uses key switch hints only for scenarios where security is not of critical 
	* importance.
	*
	* @param &newPrivateKey private key for the new ciphertext.
	* @param *keySwitchHint the key switch hint.
	* @return resulting evalkeyswitch hint
	*/
	shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const;

	/**
	* Function for evaluating automorphism of ciphertext at index i
	*
	* @param ciphertext the input ciphertext.
	* @param i automorphism index
	* @param &evalKeys - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
	* @return resulting ciphertext
	*/
	shared_ptr<Ciphertext<Element>> EvalAutomorphism(const shared_ptr<Ciphertext<Element>> ciphertext, usint i,
		const std::map<usint, shared_ptr<LPEvalKey<Element>>> &evalKeys) const;


	/**
	* Generate automophism keys for a given private key; Uses the private key for encryption
	*
	* @param privateKey private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys
	*/
	shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> EvalAutomorphismKeyGen(const shared_ptr<LPPrivateKey<Element>> privateKey,
		const std::vector<usint> &indexList) const {
		std::string errMsg = "LPAlgorithmSHELTV::EvalAutomorphismKeyGen is not implemented for LTV SHE Scheme.";
		throw std::runtime_error(errMsg);
	}

	/**
	* Generate automophism keys for a given private key; Uses the public key for encryption
	*
	* @param publicKey public key.
	* @param privateKey private key.
	* @param indexList list of automorphism indices to be computed
	* @return returns the evaluation keys
	*/
	shared_ptr<std::map<usint, shared_ptr<LPEvalKey<Element>>>> EvalAutomorphismKeyGen(const shared_ptr<LPPublicKey<Element>> publicKey,
		const shared_ptr<LPPrivateKey<Element>> privateKey, const std::vector<usint> &indexList) const;

};

/**
* @brief This is the concrete class for the leveled version of the LTV encryption scheme, and it includes methods not included in the LPAlgorithmSHELTV. This methods include RingReduce, ModReduce, ComposedEvalMult, LevelReduce, CanRingReduce.
 *
 * There have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
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
	* Method for ComposedEvalMult.  This method performs an EvalMult on two input ciphertext, then a
	* modululus reduction and a key switch on the result.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param cipherText1 The first input ciphertext to perform multiplication on.
	* @param cipherText2 THe second input ciphertext to perform multiplication on.
	* @param quadKeySwitchHint The resultant quadratic secret key after multiplication to the secret key of the particular level.
	* @return The resulting ciphertext that can be decrypted with the secret key of the particular level.
	*/
	shared_ptr<Ciphertext<Element>> ComposedEvalMult(
		const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<Ciphertext<Element>> cipherText2,
		const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const;

	/**
	* Method for Level Reduction from sk -> sk1. 
	* This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
	*
	* @param cipherText1 is the original ciphertext to be key switched and mod reduced.
	* @param linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
	* @return the resulting ciphertext.
	*/
	shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
		const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const;

	/**
	* Function that determines if security requirements are met if ring dimension is reduced by half.
	* This method is useful for testing if a ring reduction can be performed on a ciphertext without violating
	* a security boundary for the parameter setting.
	* See the class description for citations on where the algorithms were taken from.
	*
	* @param ringDimension The original ringDimension.
	* @param &moduli The vector of moduli that is used.
	* @param rootHermiteFactor The security threshold.
	* @return True if the security threshold is satisfied in the new ring dimension.
	*/
	bool CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const;
};

/**
* @brief This is the algorithms class for to enable deatures for an LTV encryption scheme, notably public key encryption, proxy re-encryption, somewhat homomorphic encryption and/or fully homomorphic encryption. 
 *
 * There have been recent advancements in the cryptanalysis of the LTV scheme, so this protocol should be used with care, if at all.  These weaknesses are derived from subfield lattice attacks which are descibed here:
 *   - Albrecht, Martin, Shi Bai, and Léo Ducas. "A subfield lattice attack on overstretched NTRU assumptions." Annual Cryptology Conference. Springer Berlin Heidelberg, 2016.
 *   - Cheon, Jung Hee, Jinhyuck Jeong, and Changmin Lee. "An algorithm for NTRU problems and cryptanalysis of the GGH multilinear map without a low-level encoding of zero." LMS Journal of Computation and Mathematics 19.A (2016): 255-266.
 *
 * This scheme is defined here:
 *   - López-Alt, Adriana, Eran Tromer, and Vinod Vaikuntanathan. "On-the-fly multiparty computation on the cloud via multikey fully homomorphic encryption." Proceedings of the forty-fourth annual ACM symposium on Theory of computing. ACM, 2012.
 *
 * Our algorithms are informed by prior implementation efforts, including here:
 *   - Rohloff, Kurt, and David Bruce Cousins. "A scalable implementation of fully homomorphic encryption built on NTRU." International Conference on Financial Cryptography and Data Security. Springer Berlin Heidelberg, 2014.
*
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
	* Function to enable a scheme.
	* FIXME This needs to be described better.
	*
	*@param feature is the feature to enable
	*/
	void Enable(PKESchemeFeature feature);
};

}

#endif
