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
#include "../lattice/ideals.h"
#include "../utils/inttypes.h"
#include "../math/distrgen.h"
#include "../encoding/ptxtencoding.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

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
	template <class Element>
	class LPCryptoParameters{
	public:
		
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
		
		//virtual ElementParams &AccessParams() = 0;

		//@Other Methods 
		//Validates the parameters of cryptosystem up to a certain level 
		//Uses the same method as in Crypto++
		/*bool Validate(unsigned int level) const 
		{
			if (m_validationLevel > level)
				return true;

			bool pass = ValidateCorrectness(level,GetAssuranceMeasure());
			pass = pass && ValidateSecurity(level, GetSecurityMeasure());

			m_validationLevel = pass ? level+1 : 0;

			return pass;
		}*/
		
		//Represent the lattice in binary format
		//virtual void DecodeElement(const Element &element, ByteArray  *text) const = 0;
		
		//Convert binary string to lattice format
		//virtual void EncodeElement(const ByteArray &encoded, Element *element) const = 0;
	
	private:
		mutable usint m_validationLevel;
	};

	/**
	 * @brief Abstract interface class for LP Keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPKey{
		public:
			/**
			 * Gets a read-only reference to an LPCryptoParameters-derived class
			 * @return the crypto parameters.
			 */
			virtual const LPCryptoParameters<Element> &GetAbstractCryptoParameters() const = 0;
			/**
			 * Gets a writable reference to an LPCryptoParameters-derived class
			 * @return the crypto parameters.
			 */
			virtual LPCryptoParameters<Element> &AccessAbstractCryptoParameters() = 0;
	};

	/**
	 * @brief Abstract interface for LP public keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKey : public LPKey<Element>{
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
			virtual const Element &GetGeneratedElement() const = 0;

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
			virtual void SetGeneratedElement (const Element &element) = 0;

	};

	/**
	 * @brief Abstract interface for LP private keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPrivateKey : public LPKey<Element>{
		public:

			//@Get Properties
			
			/**
			 * Gets the private key polynomial 
			 * @return the private key element.
			 */ 
			virtual const Element & GetPrivateElement() const = 0;

			/**
			 * Gets the private key error polynomial 
			 * @return the private key error element.
			 */  
			virtual const Element & GetPrivateErrorElement() const = 0;

			//@Set Properties
			
			/**
			 * Sets the private key polynomial
			 * @param &x the public key element.
			 */ 
			virtual void SetPrivateElement(const Element &x) = 0;
			
			/**
			 * Sets the private key error polynomial
			 * @param &x the public key error polynomial.
			 */ 
			virtual void SetPrivateErrorElement(const Element &x) = 0;

			//@Other Methods 
			/**
			 * Computes the public key using the parameters stored in implementations of LPPublicKey and LPPrivateKey interfaces 
			 * @param &pub the public key element.
			 */ 
			virtual void MakePublicKey(LPPublicKey<Element> &pub) const = 0;
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
			 * @param &dg discrete Gaussian generator.
			 * @param &plaintext the plaintext input.
			 * @param *ciphertext ciphertext which results from encryption.
			 */
			virtual void Encrypt(const LPPublicKey<Element> &publicKey, 
				DiscreteGaussianGenerator &dg, 
				const PlaintextEncodingInterface &plaintext, 
				Element *ciphertext) const = 0;
			
			/**
			 * Method for decrypting plaintext using LBC
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecodingResult Decrypt(const LPPrivateKey<Element> &privateKey, 
				const Element &ciphertext,  
				PlaintextEncodingInterface *plaintext) const = 0;

			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @param &dgg discrete Gaussian generator.
			 * @return function ran correctly.
			 */
			virtual bool KeyGen(LPPublicKey<Element> &publicKey, 
				LPPrivateKey<Element> &privateKey, 
				DiscreteGaussianGenerator &dgg) const = 0;

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
			 * @param &ddg discrete Gaussian generator.
			 * @param *evalKey the evaluation key.
			 * @return the re-encryption key.
			 */
			virtual bool ProxyKeyGen(const LPPublicKey<Element> &newPublicKey, 
				LPPrivateKey<Element> &origPrivateKey,
				DiscreteGaussianGenerator &ddg, std::vector<Element> *evalKey) const = 0;
						
			/**
			 * Virtual function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
			 *
			 * @param &evalKey proxy re-encryption key.
			 * @param &params re-ecryption parameters.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void ReEncrypt(const std::vector<Element> &evalKey, 
				const LPCryptoParameters<Element> &params,
				const Element &ciphertext, 
				Element *newCiphertext) const = 0;
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
			 * @param &params re-ecryption parameters.
			 * @param &ciphertext1 the input ciphertext.
			 * @param &ciphertext2 the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void EvalAdd(const LPCryptoParameters<Element> &params,
				const Element &ciphertext1, 
				const Element &ciphertext2, 
				Element *newCiphertext) const = 0;
	};

	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPSHEAlgorithm : public LPAHEAlgorithm<Element> {
		public:
						
			/**
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext
			 *
			 * @param &params re-ecryption parameters.
			 * @param &ciphertext1 the input ciphertext.
			 * @param &ciphertext2 the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void EvalMult(const LPCryptoParameters<Element> &params,
				const Element &ciphertext1, 
				const Element &ciphertext2, 
				Element *newCiphertext) const = 0;
	};

	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPFHEAlgorithm : public LPSHEAlgorithm<Element> {
		public:
						
			/**
			 * Virtual function to define the interface for bootstrapping evaluation of ciphertext
			 *
			 * @param &params parameters.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual void Bootstrap(const LPCryptoParameters<Element> &params,
				const Element &ciphertext, 
				Element *newCiphertext) const = 0;
	};

	/**
	 * @brief main implementation class to capture essential cryptoparameters of any LBC system
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPCryptoParametersImpl : public LPCryptoParameters<Element>
	{		
	};

//	class PKCS8PrivateKey;
//	class X509PublicKey;


	/**
	 * @brief Implementation class for private and public keys
	 * @tparam CP a cryptoparameter
	 */
	template <class Element>
	class LPKeyImpl {
		
		public:

			/**
			 * Get Crypto Parameters.
			 * @return the crypto parameters.
			 */
			const LPCryptoParameters<Element> &GetCryptoParameters() const {return *m_cryptoParameters;}

			/**
			 * Access Crypto Parameters.
			 * @return the crypto parameters.
			 */
			LPCryptoParameters<Element> &AccessCryptoParameters() { return *m_cryptoParameters; }
		private:
			LPCryptoParameters<Element> *m_cryptoParameters;
	};

	//! Implementation class for private key
	// PKCS8PrivateKey will be implemented later - copied from Crypto++
	/**
	 * @brief Implementation class for private keys
	 * @tparam Element a ring element
	 */
	template <class Element>
	class LPPrivateKeyImpl: public LPPrivateKey<Element>, public LPKeyImpl<Element>{
		public:

			/**
			 * Validate that a key is correct.  This is stubbed out for now.
			 * @param level
			 * @return validate the parameters.
			 */
			bool Validate(unsigned int level) const;

			//computes a ``small'' coefficient polynomial
			//Generator depends on the type of element; should be implemented at the element level
			//Element & GenerateElement (DistributionGenerator &dg) const;
			
			/**
			 * Get Abstract Crypto Parameters.
			 * @return get the parameters.
			 */
			const LPCryptoParameters<Element> &GetAbstractCryptoParameters() const {return this->GetCryptoParameters();}
			
			/**
			 * Access Abstract Crypto Parameters.
			 * @return the parameters accessed.
			 */
			LPCryptoParameters<Element> &AccessAbstractCryptoParameters() {return this->AccessCryptoParameters();}
			
			/**
			 * Implementation of the Get accessor for private element.
			 * @return the private element.
			 */
			const Element & GetPrivateElement() const {return m_sk;}
			
			/**
			 * Implementation of the Get accessor for auxiliary polynomial used along with the private element.
			 * @return the private error element.
			 */
			const Element & GetPrivateErrorElement() const {return m_e;}

			/**
			 * Implementation of the Set accessor for private element.
			 * @private &x the private element.
			 */
			void SetPrivateElement(const Element &x) {m_sk = x;}

			/**
			 * Implementation of the Set accessor for auxiliary polynomial used along with the private element.
			 * @private &x the private error element.
			 */
			void SetPrivateErrorElement(const Element &x) {m_e = x;}
			
			/**
			 * Can be redefined in derived classes (to support both NTRU and Ring-LWE schemes).
			 * @private &pub the public key.
			 */
			virtual void MakePublicKey(LPPublicKey<Element> &pub) const {};

		private:
			//private key polynomial
			Element m_sk;
			//error polynomial
			Element m_e;

	};

	template <class Element>
	/**
	 * @brief Implementation class for public key	
	 * @tparam Element a ring element
	 */
	class LPPublicKeyImpl : public LPPublicKey<Element>, public LPKeyImpl<Element>{	
		public:
			
			/**
			 * Validate a key. This is stubbed out for now.
			 * @param level
			 * @return validate the parameters.
			 */
			bool Validate(unsigned int level) const;
			
			//Used to generate a small polynomial
			//should be implemented at the element level
			//Element & GenerateGaussianElement (DiscreteGaussianGenerator &dgg, int expectedValue) const;
			
			//Used to generate a random component in the case of Ring-LWE public keys
			//should be implemented at the GetAbstractCryptoParameters level
			//Element & GenerateRandomElement (RandomNumberGenerator &rng, const NameValuePairs &parameters) const;

			/**
			 * Get Abstract Crypto Parameters.
			 * @return get the parameters.
			 */
			const LPCryptoParameters<Element> &GetAbstractCryptoParameters() const {return this->GetCryptoParameters();}

			/**
			 * Access Abstract Crypto Parameters.
			 * @return the parameters accessed.
			 */
			LPCryptoParameters<Element> &AccessAbstractCryptoParameters() {return this->AccessCryptoParameters();}
			
			/**
			 * Implementation of the Get accessor for public element.
			 * @return the private element.
			 */
			const Element & GetPublicElement() const {return m_h;}

			/**
			 * Implementation of the Get accessor for auxiliary polynomial used together with the public element.
			 * @return the generated element.
			 */
			const Element & GetGeneratedElement() const {return m_g;}
			
			/**
			 * Implementation of the Set accessor for public element.
			 * @private &x the public element.
			 */
			void SetPublicElement(const Element &x) {m_h = x;}

			/**
			 * Implementation of the Set accessor for generated element.
			 * @private &x the generated element.
			 */
			void SetGeneratedElement(const Element &x) {m_g = x;}

		private:
			//polynomials used for public key
			Element m_g;
			Element m_h;
	};

} // namespace lbcrypto ends
#endif
