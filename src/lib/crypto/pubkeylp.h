/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
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
 * This file contains the core public key interface functionality.
 */

#ifndef LBCRYPTO_CRYPTO_PUBKEYLP_H
#define LBCRYPTO_CRYPTO_PUBKEYLP_H

//Includes Section
#include <vector>
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilelement.h"
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../encoding/ptxtencoding.h"


/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	//forward declaration of Ciphertext class; used to resolve circular header dependency
	template <class Element>
	class Ciphertext;

	/** 
	 * @brief Decoding output.  This represents whether the decoding/decryption of a cipheretext was performed correctly.
	 *
         * This is intended to eventually incorporate information about the amount of padding in a decoded ciphertext, to ensure that the correct amount of padding is stripped away.
	 * It is intended to provided a very simple kind of checksum eventually.
	 * This notion of a decoding output is inherited from the crypto++ library.
	 * It is also intended to be used in a recover and restart robust functionality if not all ciphertext is recieved over a lossy channel, so that if all information is eventually recieved, decoding/decryption can be performed eventually.
	 * This is intended to be returned with the output of a decoding/decryption operation.
	 */
	struct DecodingResult
	{
		/**
		 * Constructor that initializes all message lengths to 0.
		 */
		explicit DecodingResult() : isValidCoding(false), messageLength(0) {}

		/**
		 * Constructor that initializes all message lengths.
		 * @param len the new length.
		 */
		explicit DecodingResult(size_t len) : isValidCoding(true), messageLength(len) {}

		bool isValidCoding; /**< whether the input is a valid encoding */
		usint messageLength; /**< Message length */
	};

	/**
	 * @brief Abstract Interface Class to capture common Crypto Parameters 
	 * @tparam Element a ring element.
	 */
	//JSON FACILITY
	template <class Element>
	class LPCryptoParameters : public Serializable {
	public:
		virtual ~LPCryptoParameters() {}
		
		//@Get Properties
	
		/**
		 * Gets the value of plaintext modulus p
		 */
		virtual const BigBinaryInteger & GetPlaintextModulus() const = 0;

		//@Set Properties

		/**
		 * Sets the value of plaintext modulus p
		 * @param &plaintextModulus the new plaintext modulus.
		 */
		virtual void SetPlaintextModulus(const BigBinaryInteger &plaintextModulus) = 0;

		/**
		 * Gets the value of element parameters
		 */
		virtual const ElemParams &GetElementParams() const = 0;
		
		virtual bool operator==(const LPCryptoParameters<Element>*) const = 0;

	};

	/**
	 * @brief Abstract interface class for LP Keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPKey : public Serializable {
		public:
			/**
			 * Gets a read-only reference to an LPCryptoParameters-derived class
			 * @return the crypto parameters.
			 */
			virtual const LPCryptoParameters<Element> &GetCryptoParameters() const = 0;

			/**
			 * Gets a writable reference to an LPCryptoParameters-derived class
			 * @return the crypto parameters.
			 */
			virtual LPCryptoParameters<Element> &AccessCryptoParameters() = 0;

			/**
			 * Sets crypto params.
			 *
			 * @param *cryptoParams parameters.
			 * @return the crypto parameters.
			 */
			virtual void SetCryptoParameters(LPCryptoParameters<Element> *cryptoParams) = 0;
	};

	/**
	 * @brief Abstract interface for LP public keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKey : public LPKey<Element> {
		public:
			
			//@Get Properties

			/**
			 * Gets the computed public key 
			 * @return the public key element.
			 */
			virtual const Element &GetPublicElement() const = 0;
			
			/**
			 * Gets the generated polynomial used in computing the public key
			 * @return the public key element.
			 */
			//virtual const Element &GetGeneratedElement() const = 0;

			//@Set Properties

			/**
			 * Sets the public key 
			 * @param &element the public key element.
			 */
			virtual void SetPublicElement (const Element &element) = 0;
			
			/**
			 * Sets the generated polynomial used in computing the public key
			 * @param &element the public key polynomial.
			 */
			//virtual void SetGeneratedElement (const Element &element) = 0;

	};

	/**
	* @brief Abstract interface for LP evaluation/proxy keys
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKey : public LPKey<Element> {
	public:

		//@Get Properties

		/**
		* Gets the computed evaluation key
		* @return the eval key elements.
		*/
		virtual const std::vector<Element> &GetEvalKeyElements() const = 0;

		/**
		* Gets the public key associated with the evaluation key
		* @return the public key element.
		*/
		virtual const LPPublicKey<Element> &GetPublicKey() const = 0;

		/**
		* Gets a writeable copy of the computed evaluation key
		* @return the private element.
		*/
		virtual std::vector<Element> &AccessEvalKeyElements() = 0;

		/**
		* Sets the evaluation key
		* @param &elements the evaluation key elements.
		*/
		virtual void SetEvalKeyElements(std::vector<Element> &elements) = 0;

		/**
		* Sets the public key
		* @param &publicKey the public key
		*/
		virtual void SetPublicKey(const LPPublicKey<Element> &publicKey) = 0;

	};

	/**
	 * @brief Abstract interface for LP private keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPrivateKey : public LPKey<Element> {
		public:

			//@Get Properties
			
			/**
			 * Gets the private key polynomial 
			 * @return the private key element.
			 */ 
			virtual const Element & GetPrivateElement() const = 0;

			//@Set Properties
			
			/**
			 * Sets the private key polynomial
			 * @param &x the public key element.
			 */ 
			virtual void SetPrivateElement(const Element &x) = 0;

			//@Other Methods 
			/**
			 * Computes the public key using the parameters stored in implementations of LPPublicKey and LPPrivateKey interfaces 
			 * @param &g a generated polynomial.
			 * @param &pub the public key element.
			 */ 
			virtual void MakePublicKey(const Element &g, LPPublicKey<Element> *pub) const = 0;

	
	};


	/**
	 * @brief Abstract interface for LP key switch hints
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPKeySwitchHint : public LPKey<Element> {
		public:

			//@Get Properties
			
			/**
			 * Gets the private key polynomial 
			 * @return the private key element.
			 */ 
			virtual const Element & GetHintElement() const = 0;

			//@Set Properties
			
			/**
			 * Sets the private key polynomial
			 * @param &x the public key element.
			 */ 
			virtual void SetHintElement(const Element &x) = 0;
	};

	/**
	 * @brief Abstract interface for encryption algorithm
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPEncryptionAlgorithm {
		public:	

			/**
			 * Method for encrypting plaintex using LBC
			 *
			 * @param &publicKey public key used for encryption.
			 * @param &plaintext the plaintext input.
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			virtual void Encrypt(const LPPublicKey<Element> &publicKey, 
				const PlaintextEncodingInterface &plaintext, 
				Ciphertext<Element> *ciphertext) const = 0;

			/**
			 * Method for encrypting plaintex using LBC
			 *
			 * @param &publicKey public key used for encryption.
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			virtual void Encrypt(const LPPublicKey<Element> &publicKey, 
				Ciphertext<Element> *ciphertext) const = 0;
			
			/**
			 * Method for decrypting plaintext using LBC
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecodingResult Decrypt(const LPPrivateKey<Element> &privateKey, 
				const Ciphertext<Element> &ciphertext,
				PlaintextEncodingInterface *plaintext) const = 0;

			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @return function ran correctly.
			 */
			virtual bool KeyGen(LPPublicKey<Element> *publicKey, 
				LPPrivateKey<Element> *privateKey) const = 0;

			virtual bool SparseKeyGen(LPPublicKey<Element> &publicKey, 
		        	LPPrivateKey<Element> &privateKey, 
			        const DiscreteGaussianGenerator &dgg) const = 0;

	};


	/**
	 * @brief Abstract interface for Leveled SHE operations
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPLeveledSHEAlgorithm {
		public:	

			/**
			 * Method for KeySwitchHintGen
			 *
			 * @param &originalPrivateKey Original private key used for encryption.
			 * @param &newPrivateKey New private key to generate the keyswitch hint.
			 * @param *KeySwitchHint is where the resulting keySwitchHint will be placed.
			 */
			virtual void KeySwitchHintGen(const LPPrivateKey<Element> &originalPrivateKey, 
				const LPPrivateKey<Element> &newPrivateKey, LPKeySwitchHint<Element> *keySwitchHint) const = 0;
			
			/**
			 * Method for KeySwitch
			 *
			 * @param &keySwitchHint Hint required to perform the ciphertext switching.
			 * @param &cipherText Original ciphertext to perform switching on.
			 */
			virtual Ciphertext<Element> KeySwitch(const LPKeySwitchHint<Element> &keySwitchHint, const Ciphertext<Element> &cipherText) const = 0;

			virtual void QuadraticKeySwitchHintGen(const LPPrivateKey<Element> &originalPrivateKey, const LPPrivateKey<Element> &newPrivateKey, LPKeySwitchHint<Element> *quadraticKeySwitchHint) const = 0;

			/**
			 * Method for ModReduce
			 *
			 * @param &cipherText Ciphertext to perform mod reduce on.
			 * @param &privateKey Private key used to encrypt the first argument.
			 */
			virtual void ModReduce(Ciphertext<Element> *cipherText) const = 0; 

			/**
			 * Method for RingReduce
			 *
			 * @param &cipherText Ciphertext to perform ring reduce on.
			 * @param &privateKey Private key used to encrypt the first argument.
			 */
			virtual void RingReduce(Ciphertext<Element> *cipherText, const LPKeySwitchHint<Element> &keySwitchHint) const = 0; 

			/**
			 * Method for Composed EvalMult
			 *
			 * @param &cipherText Ciphertext1, Ciphertext2 to perform multiplication on.
			 * @param &quadKeySwitchHint is the quadratic key switch hint.
			 */
			virtual void ComposedEvalMult(const Ciphertext<Element> &cipherText1, const Ciphertext<Element> &cipherText2, const LPKeySwitchHint<Element> &quadKeySwitchHint, Ciphertext<Element> *cipherTextResult) const = 0;

			/**
			 * Method for Level Reduction from sk -> sk1.
			 *
			 * @param &cipherText Ciphertext1, Ciphertext2 to perform multiplication on.
			 * @param &linearKeySwitchHint is the linear key switch hint.
			 */
			virtual void LevelReduce(const Ciphertext<Element> &cipherText1, const LPKeySwitchHint<Element> &linearKeySwitchHint, Ciphertext<Element> *cipherTextResult) const = 0;

	};

	/**
	 * @brief Abstract interface class for LBC PRE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPREAlgorithm {
		public:

			/**
			 * Virtual function to generate 1..log(q) encryptions for each bit of the original private key
			 *
			 * @param &newPublicKey encryption key for the new ciphertext.
			 * @param &origPrivateKey original private key used for decryption.
			 * @param *evalKey the evaluation key.
			 * @return the re-encryption key.
			 */
			virtual bool EvalKeyGen(const LPPublicKey<Element> &newPublicKey, 
				const LPPrivateKey<Element> &origPrivateKey,
				LPEvalKey<Element> *evalKey) const = 0;
						
			/**
			 * Virtual function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
			 *
			 * @param &evalKey proxy re-encryption key.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void ReEncrypt(const LPEvalKey<Element> &evalKey, 
				const Ciphertext<Element> &ciphertext,
				Ciphertext<Element> *newCiphertext) const = 0;
	};



	/**
	 * @brief Abstract interface class for LBC AHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAHEAlgorithm {
		public:		
			/**
			 * Virtual function to define the interface for additive homomorphic evaluation of ciphertext
			 *
			 * @param &ciphertext1 the input ciphertext.
			 * @param &ciphertext2 the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void EvalAdd(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const = 0;
	};

	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPSHEAlgorithm {
		public:
						
			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext
			 *
			 * @param &ciphertext1 the input ciphertext.
			 * @param &ciphertext2 the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const = 0;

			virtual void EvalAdd(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const = 0;

	};

	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPFHEAlgorithm {
		public:
						
			/**
			 * Virtual function to define the interface for bootstrapping evaluation of ciphertext
			 *
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void Bootstrap(const Ciphertext<Element> &ciphertext,
				Ciphertext<Element> *newCiphertext) const = 0;
	};

	/**
	 * @brief Abstract interface class for automorphism-based SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAutoMorphAlgorithm {
		public:
						
			/**
			 * Virtual function to define the interface for evaluating ciphertext at an index
			 *
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void EvalAtIndex(const Ciphertext<Element> &ciphertext, const usint i, const std::vector<LPEvalKey<Element> *> &evalKeys,
				Ciphertext<Element> *newCiphertext) const = 0;

			/**
			 * Virtual function to generate all isomorphism keys for a given private key
			 *
			 * @param &publicKey encryption key for the new ciphertext.
			 * @param &origPrivateKey original private key used for decryption.
			 * @param *evalKeys the evaluation keys.
			 * @return a vector of re-encryption keys.
			 */
			virtual bool EvalAutomorphismKeyGen(const LPPublicKey<Element> &publicKey, 
				const LPPrivateKey<Element> &origPrivateKey,
				const usint size, LPPrivateKey<Element> *tempPrivateKey, 
				std::vector<LPEvalKey<Element> *> *evalKeys) const = 0;
	};




	


	/**
	 * @brief main implementation class to capture essential cryptoparameters of any LBC system
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPCryptoParametersImpl : public LPCryptoParameters<Element>
	{		
	public:

		/**
			* Returns the value of plaintext modulus p
			*
			* @return the plaintext modulus.
			*/
		const BigBinaryInteger &GetPlaintextModulus() const {return  m_plaintextModulus;}

			//LPCryptoParameters<Element> &AccessCryptoParameters() { return *m_cryptoParameters; } 

			///**
			// * Sets crypto params.
			// *
			// * @param *cryptoParams parameters.
			// * @return the crypto parameters.
			// */
			//void SetCryptoParameters( LPCryptoParameters<Element> *cryptoParams) { 
			//	m_cryptoParameters = cryptoParams; 
			//}

		/**
			* Returns the reference to IL params
			*
			* @return the ring element parameters.
			*/
		const ElemParams &GetElementParams() const { return *m_params; }

		//@Set Properties
			
		/**
			* Sets the value of plaintext modulus p
			*/
		void SetPlaintextModulus(const BigBinaryInteger &plaintextModulus) {m_plaintextModulus = plaintextModulus;}
			
		/**
			* Sets the reference to element params
			*/
		void SetElementParams(ElemParams &params) { m_params = &params; }

		bool operator==(const LPCryptoParameters<Element>* cmp) const {
			return m_plaintextModulus == cmp->GetPlaintextModulus() && cmp->GetElementParams() == m_params;
		}

	protected:
		LPCryptoParametersImpl() : m_params(NULL), m_plaintextModulus(BigBinaryInteger::TWO) {}

		LPCryptoParametersImpl(ElemParams *params, const BigBinaryInteger &plaintextModulus) : m_params(params), m_plaintextModulus(plaintextModulus) {}

	private:
		//element-specific parameters
		ElemParams *m_params;
		//plaintext modulus p
		BigBinaryInteger m_plaintextModulus;
	};

	
	/**
	 * @brief Abstract interface for public key encryption schemes
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyEncryptionScheme : public LPEncryptionAlgorithm<Element>, public LPPREAlgorithm<Element> {
	public:
		
		//to be implemented later
		//void Disable(PKESchemeFeature feature);
		
		const std::bitset<FEATURESETSIZE> GetEnabledFeatures() {return m_featureMask;}
		
		//to be implemented later
		//const std::string PrintEnabledFeatures();
		
		//needs to be moved to pubkeylp.cpp
		bool IsEnabled(PKESchemeFeature feature) const {
			bool flag = false;
			switch (feature)
			  {
				 case ENCRYPTION:
					if (m_algorithmEncryption != NULL)
						flag = true;
					break;
				 case PRE:
					if (m_algorithmPRE!= NULL)
						flag = true;
					break;
				 case EVALADD:
					if (m_algorithmEvalAdd!= NULL)
						flag = true;
					break;
				 case EVALAUTOMORPHISM:
					if (m_algorithmEvalAutomorphism!= NULL)
						flag = true;
					break;
				 case SHE:
					if (m_algorithmSHE!= NULL)
						flag = true;
					break;
				 case FHE:
					if (m_algorithmFHE!= NULL)
						flag = true;
					break;
				 case LEVELEDSHE:
					if (m_algorithmLeveledSHE!= NULL)
						flag = true;
					break;
			  }
			return flag;
		}

		//instantiated in the scheme implementation class
		virtual void Enable(PKESchemeFeature feature) = 0;

		const LPAutoMorphAlgorithm<Element> &GetLPAutoMorphAlgorithm() {
			if(this->IsEnabled(EVALAUTOMORPHISM))
				return *m_algorithmEvalAutomorphism;
			else
				throw std::logic_error("This operation is not supported");
		}

		//wrapper for Encrypt method
		void Encrypt(const LPPublicKey<Element> &publicKey, 
			const PlaintextEncodingInterface &plaintext, Ciphertext<Element> *ciphertext) const {
				if(this->IsEnabled(ENCRYPTION))
					this->m_algorithmEncryption->Encrypt(publicKey,plaintext,ciphertext);
				else {
					throw std::logic_error("This operation is not supported");
				}
		}

		//wrapper for Encrypt method
		void Encrypt(const LPPublicKey<Element> &publicKey, 
			Ciphertext<Element> *ciphertext) const {
				if(this->IsEnabled(ENCRYPTION))
					return this->m_algorithmEncryption->Encrypt(publicKey, ciphertext);
				else {
					throw std::logic_error("This operation is not supported");
				}
		}

		//wrapper for Decrypt method
		DecodingResult Decrypt(const LPPrivateKey<Element> &privateKey, const Ciphertext<Element> &ciphertext,
				PlaintextEncodingInterface *plaintext) const {
				if(this->IsEnabled(ENCRYPTION))
					return this->m_algorithmEncryption->Decrypt(privateKey,ciphertext,plaintext);
				else {
					throw std::logic_error("This operation is not supported");
				}
		}

		//wrapper for KeyGen method
		bool KeyGen(LPPublicKey<Element> *publicKey, LPPrivateKey<Element> *privateKey) const {
				if(this->IsEnabled(ENCRYPTION))
					return this->m_algorithmEncryption->KeyGen(publicKey,privateKey);
				else {
					throw std::logic_error("This operation is not supported");
				}
		}

		bool SparseKeyGen(LPPublicKey<Element> &publicKey, 
		        	LPPrivateKey<Element> &privateKey, 
			        const DiscreteGaussianGenerator &dgg) const {
				if(this->IsEnabled(ENCRYPTION))
					return this->m_algorithmEncryption->SparseKeyGen(publicKey, privateKey, dgg);
				else {
					throw std::logic_error("This operation is not supported");
				}
				
		}

		//wrapper for EvalKeyGen method
		bool EvalKeyGen(const LPPublicKey<Element> &newPublicKey, const LPPrivateKey<Element> &origPrivateKey,
			LPEvalKey<Element> *evalKey) const{
				if(this->IsEnabled(PRE))
					return this->m_algorithmPRE->EvalKeyGen(newPublicKey,origPrivateKey,evalKey);
				else {
					throw std::logic_error("This operation is not supported");
				}
		}

		//wrapper for ReEncrypt method
		void ReEncrypt(const LPEvalKey<Element> &evalKey, const Ciphertext<Element> &ciphertext,
			Ciphertext<Element> *newCiphertext) const {
				if(this->IsEnabled(PRE))
					this->m_algorithmPRE->ReEncrypt(evalKey,ciphertext,newCiphertext);
				else {
					throw std::logic_error("This operation is not supported");
				}
		}

//	protected:

		const LPEncryptionAlgorithm<Element> *m_algorithmEncryption;
		const LPPREAlgorithm<Element> *m_algorithmPRE;
		const LPAHEAlgorithm<Element> *m_algorithmEvalAdd;
		const LPAutoMorphAlgorithm<Element> *m_algorithmEvalAutomorphism;
		const LPSHEAlgorithm<Element> *m_algorithmSHE;
		const LPFHEAlgorithm<Element> *m_algorithmFHE;
		const LPLeveledSHEAlgorithm<Element> *m_algorithmLeveledSHE;
		std::bitset<FEATURESETSIZE> m_featureMask;
	};


	/**
	 * @brief main implementation class for public key encryption algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyEncryptionAlgorithmImpl
	{		
	public:

		//gets reference to the scheme
		const LPPublicKeyEncryptionScheme<Element> &GetScheme() const {return *m_scheme;}

		//@Set Properties
		/**
			* Sets the reference to element params
			*/
		void SetScheme(const LPPublicKeyEncryptionScheme<Element> &scheme) { m_scheme = &scheme; }

	protected:
		LPPublicKeyEncryptionAlgorithmImpl() : m_scheme(NULL) {}

		LPPublicKeyEncryptionAlgorithmImpl(const LPPublicKeyEncryptionScheme<Element> &scheme) : m_scheme(&scheme) {}

	private:
		//pointer to the parent scheme
		const LPPublicKeyEncryptionScheme<Element> *m_scheme;
	};


} // namespace lbcrypto ends
#endif
