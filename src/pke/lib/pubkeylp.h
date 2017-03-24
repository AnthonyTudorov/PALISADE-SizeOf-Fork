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
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "utils/serializablehelper.h"


/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	//forward declaration of Ciphertext class; used to resolve circular header dependency
	template <class Element>
	class Ciphertext;

	//forward declaration of RationalCiphertext class; used to resolve circular header dependency
	template <class Element>
	class RationalCiphertext;

	//forward declaration of LPCryptoParameters class;
	template <class Element>
	class LPCryptoParameters;

	//forward declaration of LPCryptoParametersLTV class;
	template <class Element>
	class LPCryptoParametersLTV;

	//forward declaration of LPCryptoParametersBV class;
	template <class Element>
	class LPCryptoParametersBV;

	//forward declaration of LPCryptoParametersStehleSteinfeld class;
	template <class Element>
	class LPCryptoParametersStehleSteinfeld;

	struct EncryptResult {

		explicit EncryptResult() : isValid(false), numBytesEncrypted(0) {}

		explicit EncryptResult(size_t len) : isValid(true), numBytesEncrypted(len) {}

		bool isValid;				/**< whether the encryption was successful */
		usint	numBytesEncrypted;	/**< count of the number of plaintext bytes that were encrypted */
	};

	/** 
	 * @brief Decryption result.  This represents whether the decryption of a cipheretext was performed correctly.
	 *
     * This is intended to eventually incorporate information about the amount of padding in a decoded ciphertext,
     * to ensure that the correct amount of padding is stripped away.
	 * It is intended to provided a very simple kind of checksum eventually.
	 * This notion of a decoding output is inherited from the crypto++ library.
	 * It is also intended to be used in a recover and restart robust functionality if not all ciphertext is recieved over a lossy channel, so that if all information is eventually recieved, decoding/decryption can be performed eventually.
	 * This is intended to be returned with the output of a decryption operation.
	 */
	struct DecryptResult {
		/**
		 * Constructor that initializes all message lengths to 0.
		 */
		explicit DecryptResult() : isValid(false), messageLength(0) {}

		/**
		 * Constructor that initializes all message lengths.
		 * @param len the new length.
		 */
		explicit DecryptResult(size_t len) : isValid(true), messageLength(len) {}

		bool isValid;			/**< whether the decryption was successful */
		usint messageLength;	/**< the length of the decrypted plaintext message */
	};

	/**
	 * @brief Abstract interface class for LP Keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPKey : public Serializable {
	public:

		LPKey(const CryptoContext<Element>& cc) : cryptoContext(cc) {}

		virtual ~LPKey() {}

		/**
		 * Gets a read-only reference to an LPCryptoParameters-derived class
		 * @return the crypto parameters.
		 */
		const CryptoContext<Element>& GetCryptoContext() const { return cryptoContext; }

		/**
		 * Gets a read-only reference to an LPCryptoParameters-derived class
		 * @return the crypto parameters.
		 */
		const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return cryptoContext.GetCryptoParameters(); }

	protected:
		CryptoContext<Element>	cryptoContext;
	};

	/**
	 * @brief Concrete class for LP public keys
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKey : public LPKey<Element> {
		public:

			/**
			* Basic constructor for setting crypto params
			*
			* @param &cryptoParams is the reference to cryptoParams
			*/
			LPPublicKey(const CryptoContext<Element>& cc) : LPKey<Element>(cc) {}

			/**
			* Copy constructor
			*
			*@param &rhs LPPublicKey to copy from
			*/
			explicit LPPublicKey(const LPPublicKey<Element> &rhs) {
				m_h = rhs.m_h;
				this->m_cryptoParameters = rhs.m_cryptoParameters;
			}

			/**
			* Move constructor
			*
			*@param &rhs LPPublicKey to move from
			*/
			explicit LPPublicKey(LPPublicKey<Element> &&rhs) {
				m_h = std::move(rhs.m_h);
				this->m_cryptoParameters = rhs.m_cryptoParameters;
			}

			/**
			* Assignment Operator.
			*
			* @param &rhs LPPublicKey to copy from
			*/
			const LPPublicKey<Element>& operator=(const LPPublicKey<Element> &rhs) {
				this->m_h = rhs.m_h;
				this->m_cryptoParameters = rhs.m_cryptoParameters;

				return *this;
			}

			/**
			* Move Assignment Operator.
			*
			* @param &rhs LPPublicKey to copy from
			*/
			const LPPublicKey<Element>& operator=(LPPublicKey<Element> &&rhs) {
				m_h = std::move(rhs.m_h);
				this->m_cryptoParameters = rhs.m_cryptoParameters;

				return *this;
			}

			//@Get Properties

			/**
			 * Gets the computed public key 
			 * @return the public key element.
			 */
			const std::vector<Element> &GetPublicElements() const {
				return this->m_h;
			}
			
			//@Set Properties

			/**
			 * Sets the public key vector of Element.
			 * @param &element is the public key Element vector to be copied.
			 */
			void SetPublicElements(const std::vector<Element> &element) {
				m_h = element;
			}

			/**
			* Sets the public key vector of Element.
			* @param &&element is the public key Element vector to be moved.
			*/
			void SetPublicElements(std::vector<Element> &&element) {
				m_h = std::move(element);
			}

			/**
			* Sets the public key Element at index idx.
			* @param &element is the public key Element to be copied.
			*/
			void SetPublicElementAtIndex(usint idx, const Element &element) {
				m_h.insert(m_h.begin() + idx, element);
			}

			/**
			* Sets the public key Element at index idx.
			* @param &&element is the public key Element to be moved.
			*/
			void SetPublicElementAtIndex(usint idx, Element &&element) {
				m_h.insert(m_h.begin() + idx, std::move(element));
			}
			
			//JSON FACILITY
			/**
			* Serialize the object into a Serialized
			* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @param fileFlag is an object-specific parameter for the serialization
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized *serObj) const {
				serObj->SetObject();

				serObj->AddMember("Object", "PublicKey", serObj->GetAllocator());

				if (!this->GetCryptoParameters()->Serialize(serObj)) {
					return false;
				}

				SerializeVector<Element>("Vectors", elementName<Element>(), this->GetPublicElements(), serObj);

				return true;
			}

			/**
			* Populate the object from the deserialization of the Serialized
			* @param &serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized &serObj) { 

				Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
				if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "PublicKey" )
					return false;

				mIt = serObj.FindMember("Vectors");

				if( mIt == serObj.MemberEnd() ) {
					return false;
				}

				bool ret = DeserializeVector<Element>("Vectors", elementName<Element>(), mIt, &this->m_h);

				return ret;
			}

	private:
		std::vector<Element> m_h;

	};

	/**
	* @brief Abstract interface for LP evaluation/proxy keys
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKey : public LPKey<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKey(const CryptoContext<Element>& cc) : LPKey<Element>(cc) {}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element vector to be copied.
		*/

		virtual void SetAVector(const std::vector<Element> &a) {
			throw std::runtime_error("SetAVector copy operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element vector to be moved.
		*/

		virtual void SetAVector(std::vector<Element> &&a) {
			throw std::runtime_error("SetAVector move operation not supported");
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Throws exception, to be overridden by derived class.
		*
		* @return Element vector A.
		*/

		virtual const std::vector<Element> &GetAVector() const {
			throw std::runtime_error("GetAVector operation not supported");
			return std::vector<Element>();
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @param &b is the Element vector to be copied.
		*/

		virtual void SetBVector(const std::vector<Element> &b) {
			throw std::runtime_error("SetBVector copy operation not supported");
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&b is the Element vector to be moved.
		*/

		virtual void SetBVector(std::vector<Element> &&b) {
			throw std::runtime_error("SetBVector move operation not supported");
		}

		/**
		* Getter function to access Relinearization Element Vector B.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element vector B.
		*/

		virtual const std::vector<Element> &GetBVector() const {
			throw std::runtime_error("GetBVector operation not supported");
			return std::vector<Element>();
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &a is the Element to be copied.
		*/

		virtual void SetA(const Element &a) {
			throw std::runtime_error("SetA copy operation not supported");
		}

		/**
		* Setter function to store key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @param &&a is the Element to be moved.
		*/
		virtual void SetA(Element &&a) {
			throw std::runtime_error("SetA move operation not supported");
		}

		/**
		* Getter function to access key switch Element.
		* Throws exception, to be overridden by derived class.
		*
		* @return  Element.
		*/

		virtual const Element &GetA() const {
			throw std::runtime_error("GetA operation not supported");
			return Element();
		}
	};

	/**
	* @brief Concrete class for Relinearization keys of RLWE scheme
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyRelin : public LPEvalKey<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/
		LPEvalKeyRelin(const CryptoContext<Element>& cc) : LPEvalKey<Element>(cc) {}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &a is the Element vector to be copied.
		*/
		virtual void SetAVector(const std::vector<Element> &a) {
			m_rKey.insert(m_rKey.begin() + 0, a);
		}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &&a is the Element vector to be moved.
		*/
		virtual void SetAVector(std::vector<Element> &&a) {
			m_rKey.insert(m_rKey.begin() + 0, std::move(a));
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @return Element vector A.
		*/
		virtual const std::vector<Element> &GetAVector() const {
			return m_rKey.at(0);
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @param &b is the Element vector to be copied.
		*/
		virtual void SetBVector(const std::vector<Element> &b) {
			m_rKey.insert(m_rKey.begin() + 1, b);
		}

		/**
		* Setter function to store Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @param &&b is the Element vector to be moved.
		*/
		virtual void SetBVector(std::vector<Element> &&b) {
			m_rKey.insert(m_rKey.begin() + 1, std::move(b));
		}

		/**
		* Getter function to access Relinearization Element Vector B.
		* Overrides base class implementation.
		*
		* @return Element vector B.
		*/
		virtual const std::vector<Element> &GetBVector() const {
			return m_rKey.at(1);
		}


		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const {
			serObj->SetObject();

			serObj->AddMember("Object", "EvalKeyRelin", serObj->GetAllocator());

			if (!this->GetCryptoParameters()->Serialize(serObj)) {
				return false;
			}

			SerializeVector<Element>("AVector", elementName<Element>(), this->m_rKey[0], serObj);
			SerializeVector<Element>("BVector", elementName<Element>(), this->m_rKey[1], serObj);

			return true;
		}

		bool Deserialize(const Serialized &serObj) {

			Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
			if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyRelin" )
				return false;

			mIt = serObj.FindMember("AVector");

			if( mIt == serObj.MemberEnd() ) {
				return false;
			}

			std::vector<Element> deserElem;
			bool ret = DeserializeVector<Element>("AVector", elementName<Element>(), mIt, &deserElem);
			this->m_rKey.push_back(deserElem);

			if( !ret ) return ret;

			mIt = serObj.FindMember("BVector");

			if( mIt == serObj.MemberEnd() ) {
				return false;
			}

			ret = DeserializeVector<Element>("BVector", elementName<Element>(), mIt, &deserElem);
			this->m_rKey.push_back(deserElem);

			return ret;
		}
	private:
		//private member to store vector of vector of Element.
		std::vector< std::vector<Element> > m_rKey;
	};

	/**
	* @brief Evaluation Relinearization keys for NTRU scheme.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyNTRURelin : public LPEvalKey<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyNTRURelin(const CryptoContext<Element>& cc) : LPEvalKey<Element>(cc) {}

		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &a is the Element vector to be copied.
		*/
		virtual void SetAVector(const std::vector<Element> &a) {
			for (usint i = 0; i < a.size(); i++) {
				m_rKey.insert(m_rKey.begin() + i, a.at(i));
			}
		}


		/**
		* Setter function to store Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @param &&a is the Element vector to be moved.
		*/
		virtual void SetAVector(std::vector<Element> &&a) {
			m_rKey = std::move(a);
		}

		/**
		* Getter function to access Relinearization Element Vector A.
		* Overrides base class implementation.
		*
		* @return Element vector A.
		*/
		virtual const std::vector<Element> &GetAVector() const {
			return m_rKey;
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const {
			serObj->SetObject();

			serObj->AddMember("Object", "EvalKeyNTRURelin", serObj->GetAllocator());

			if (!this->GetCryptoParameters()->Serialize(serObj)) {
				return false;
			}

			SerializeVector<Element>("Vectors", elementName<Element>(), this->GetAVector(), serObj);

			return true;
		}

		/**
		* Populate the object from the deserialization of the Serialized
		* @param &serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj) {
			Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
			if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyNTRURelin" )
				return false;

			SerialItem::ConstMemberIterator it = serObj.FindMember("Vectors");

			if( it == serObj.MemberEnd() ) {
				return false;
			}

			std::vector<Element> newElements;
			if( DeserializeVector<Element>("Vectors", elementName<Element>(), it, &newElements) ) {
				this->SetAVector(newElements);
				return true;
			}

			return false;
		}

		
	private:
		//private member to store vector of Element.
		std::vector<Element>  m_rKey;
	};

	/**
	* @brief Concrete class for facilitating NTRU key switch.
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPEvalKeyNTRU : public LPEvalKey<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams
		*/

		LPEvalKeyNTRU(const CryptoContext<Element>& cc) : LPEvalKey<Element>(cc) {}

		/**
		* Setter function to store NTRU key switch element.
		* Function copies the key.
		* Overrides the virtual function from base class LPEvalKey.
		*
		* @param &a is the key switch element to be copied.
		*/

		virtual void SetA(const Element &a) {
			m_Key = a;
		}

		/**
		* Setter function to store NTRU key switch Element.
		* Function moves the key.
		* Overrides the virtual function from base class LPEvalKey.
		*
		* @param &&a is the key switch Element to be moved.
		*/
		virtual void SetA(Element &&a) {
			m_Key = std::move(a);
		}

		/**
		* Getter function to access NTRU key switch Element.
		* Overrides the virtual function from base class LPEvalKey.
		*
		* @return NTRU key switch Element.
		*/

		virtual const Element& GetA() const {
			return m_Key;
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj) const {
			serObj->SetObject();

			serObj->AddMember("Object", "EvalKeyNTRU", serObj->GetAllocator());

			if (!this->GetCryptoParameters()->Serialize(serObj)) {
				return false;
			}

			const Element& pe = this->GetA();

			if (!pe.Serialize(serObj)) {
				return false;
			}

			return true;
		}

		bool Deserialize(const Serialized &serObj) {
			Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
			if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "EvalKeyNTRU" )
				return false;

			Element pe;

			if( !pe.Deserialize(serObj) ) {
				return false;
			}

			m_Key = pe;

			return true;
		}

	private:
		/**
		* private member Element to store key.
		*/
		Element m_Key;
	};
	

	/**
	* @brief Private key implementation template for Ring-LWE, NTRU-based schemes,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPrivateKey : public LPKey<Element> {
	public:

		/**
		* Basic constructor for setting crypto params
		*
		* @param &cryptoParams is the reference to cryptoParams.
		*/

		LPPrivateKey(const CryptoContext<Element>& cc) : LPKey<Element>(cc) {}

		/**
		* Copy constructor
		*@param &rhs the LPPrivateKey to copy from
		*/
		explicit LPPrivateKey(const LPPrivateKey<Element> &rhs) {
			this->m_sk = rhs.m_sk;
			this->m_cryptoParameters = rhs.m_cryptoParameters;
		}

		/**
		* Move constructor
		*@param &rhs the LPPrivateKey to move from
		*/
		explicit LPPrivateKey(LPPrivateKey<Element> &&rhs) {
			this->m_sk = std::move(rhs.m_sk);
			this->m_cryptoParameters = rhs.m_cryptoParameters;
		}

		/**
		* Assignment Operator.
		*
		* @param &rhs LPPrivateKeyto assign from.
		* @return the resulting LPPrivateKey
		*/
		const LPPrivateKey<Element>& operator=(const LPPrivateKey<Element> &rhs) {
			this->m_sk = rhs.m_sk;
			this->m_cryptoParameters = rhs.m_cryptoParameters;

			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs LPPrivateKey to assign from.
		* @return the resulting LPPrivateKey
		*/
		const LPPrivateKey<Element>& operator=(LPPrivateKey<Element> &&rhs) {
			this->m_sk = std::move(rhs.m_sk);
			this->m_cryptoParameters = rhs.m_cryptoParameters;

			return *this;
		}

		/**
		* Implementation of the Get accessor for private element.
		* @return the private element.
		*/
		const Element & GetPrivateElement() const { return m_sk; }

		/**
		* Set accessor for private element.
		* @private &x private element to set to.
		*/
		void SetPrivateElement(const Element &x) { m_sk = x; }

		/**
		* Set accessor for private element.
		* @private &x private element to set to.
		*/
		void SetPrivateElement(Element &&x) { m_sk = std::move(x); }

		bool Serialize(Serialized *serObj) const {

			serObj->SetObject();

			serObj->AddMember("Object", "PrivateKey", serObj->GetAllocator());

			if (!this->GetCryptoParameters()->Serialize(serObj))
				return false;

			return this->GetPrivateElement().Serialize(serObj);
		}

		/**
		* Populate the object from the deserialization of the Setialized
		* @param &serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj) { 
			Serialized::ConstMemberIterator mIt = serObj.FindMember("Object");
			if( mIt == serObj.MemberEnd() || string(mIt->value.GetString()) != "PrivateKey" )
				return false;

			Element json_ilElement;
			if (json_ilElement.Deserialize(serObj)) {
				this->SetPrivateElement(json_ilElement);
				return true;
			}
			return false;

		}


	private:
		Element m_sk;
	};

	template <class Element>
	class LPKeyPair {
	public:
		shared_ptr<LPPublicKey<Element>>	publicKey;
		shared_ptr<LPPrivateKey<Element>>	secretKey;

		LPKeyPair(LPPublicKey<Element>* a=0, LPPrivateKey<Element>* b=0) : publicKey(a), secretKey(b) {}

		bool good() { return publicKey && secretKey; }
		
	};

	/**
	* @brief Abstract interface for parameter generation algorithm
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPParameterGenerationAlgorithm {
	public:

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param *cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		*/
		virtual bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const = 0;

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
			virtual shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey, Element &plaintext) const = 0;

			/**
			 * Method for decrypting plaintext using LBC
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
				const shared_ptr<Ciphertext<Element>> ciphertext,
				Element *plaintext) const = 0;

			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @return function ran correctly.
			 */
			virtual LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse=false) const = 0;

	};


	/**
	 * @brief Abstract interface for Leveled SHE operations
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPLeveledSHEAlgorithm {
		public:	

			/**
			 * Method for Modulus Reduction.
			 *
			 * @param &cipherText Ciphertext to perform mod reduce on.
			 */
			virtual shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const = 0;

			/**
			 * Method for Ring Reduction.
			 *
			 * @param &cipherText Ciphertext to perform ring reduce on.
			 * @param &privateKey Private key used to encrypt the first argument.
			 */
			virtual shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const = 0;

			/**
			 * Method for Composed EvalMult
			 *
			 * @param &cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
			 * @param &cipherText2 cipherText2, second input ciphertext to perform multiplication on.
			 * @param &quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
			 * @param &cipherTextResult is the resulting ciphertext that can be decrypted with the secret key of the particular level.
			 */
			virtual shared_ptr<Ciphertext<Element>> ComposedEvalMult(
					const shared_ptr<Ciphertext<Element>> cipherText1,
					const shared_ptr<Ciphertext<Element>> cipherText2,
					const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const = 0;

			/**
			 * Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
			 *
			 * @param &cipherText1 is the original ciphertext to be key switched and mod reduced.
			 * @param &linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
			 * @param &cipherTextResult is the resulting ciphertext.
			 */
			virtual shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
					const shared_ptr<LPEvalKey<Element>> linearKeySwitchHint) const = 0;

			/**
			* Function that determines if security requirements are met if ring dimension is reduced by half.
			*
			* @param ringDimension is the original ringDimension
			* @param &moduli is the vector of moduli that is used
			* @param rootHermiteFactor is the security threshold
			*/
			virtual bool CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const = 0;
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
			 * @param &newKey new key (private or public depending on the scheme) for the new ciphertext.
			 * @param &origPrivateKey original private key used for decryption.
			 * @param *evalKey the evaluation key.
			 * @return the re-encryption key.
			 */
			virtual shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPKey<Element>> newKey,
				const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const = 0;
						
			/**
			 * Virtual function to define the interface for re-encypting ciphertext using the array generated by ProxyGen
			 *
			 * @param &evalKey proxy re-encryption key.
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
				const shared_ptr<Ciphertext<Element>> ciphertext) const = 0;
	};

	/**
	 * @brief Abstract interface class for LBC SHE algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPSHEAlgorithm {
		public:

			/**
			* Virtual function to define the interface for homomorphic addition of ciphertexts.
			*
			* @param &ciphertext1 the input ciphertext.
			* @param &ciphertext2 the input ciphertext.
			* @param *newCiphertext the new ciphertext.
			*/
			virtual shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
				const shared_ptr<Ciphertext<Element>> ciphertext2) const = 0;

			/**
			* Virtual function to define the interface for homomorphic subtraction of ciphertexts.
			*
			* @param &ciphertext1 the input ciphertext.
			* @param &ciphertext2 the input ciphertext.
			* @param *newCiphertext the new ciphertext.
			*/
			virtual shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
				const shared_ptr<Ciphertext<Element>> ciphertext2) const = 0;

			/**
			* Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext.
			*
			* @param &ciphertext1 the input ciphertext.
			* @param &ciphertext2 the input ciphertext.
			* @param *newCiphertext the new ciphertext.
			*/
			virtual shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
				const shared_ptr<Ciphertext<Element>> ciphertext2) const = 0;

			/**
			* Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext using the evaluation key.
			*
			* @param &ciphertext1 first input ciphertext.
			* @param &ciphertext2 second input ciphertext.
			* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
			* @param *newCiphertext the new resulting ciphertext.
			*/
			virtual shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
				const shared_ptr<Ciphertext<Element>> ciphertext2, const shared_ptr<LPEvalKey<Element>> ek) const = 0;

			/**
			* EvalLinRegression - Computes the parameter vector for linear regression using the least squares method
			* @param x - matrix of regressors
			* @param y - vector of dependent variables
			* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
			*/
			shared_ptr<Matrix<RationalCiphertext<Element>>>
				EvalLinRegression(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
					const shared_ptr<Matrix<RationalCiphertext<Element>>> y) const
			{
				// multiplication is done in reverse order to minimize the number of inner products
				Matrix<RationalCiphertext<Element>> xTransposed = x->Transpose();
				shared_ptr<Matrix<RationalCiphertext<Element>>> result (new Matrix<RationalCiphertext<Element>>(xTransposed * (*y)));

				Matrix<RationalCiphertext<Element>> xCovariance = xTransposed * (*x);

				Matrix<RationalCiphertext<Element>> cofactorMatrix = xCovariance.CofactorMatrix();

				Matrix<RationalCiphertext<Element>> adjugateMatrix = cofactorMatrix.Transpose();

				*result = adjugateMatrix * (*result);

				RationalCiphertext<Element> determinant;
				xCovariance.Determinant(&determinant);

				for (int row = 0; row < result->GetRows(); row++)
					for (int col = 0; col < result->GetCols(); col++)
						(*result)(row, col).SetDenominator(*determinant.GetNumerator());

				return result;

			}

			/**
			* Virtual function to define the interface for homomorphic negation of ciphertext.
			*
			* @param &ciphertext the input ciphertext.
			* @param *newCiphertext the new ciphertext.
			*/
			virtual shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const = 0;

			/**
			* Method for KeySwitchGen
			*
			* @param &originalPrivateKey Original private key used for encryption.
			* @param &newPrivateKey New private key to generate the keyswitch hint.
			* @param *KeySwitchHint is where the resulting keySwitchHint will be placed.
			*/
			virtual shared_ptr<LPEvalKey<Element>> KeySwitchGen(
				const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
				const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const = 0;

			/**
			* Method for KeySwitch
			*
			* @param &keySwitchHint Hint required to perform the ciphertext switching.
			* @param &cipherText Original ciphertext to perform switching on.
			*/
			virtual shared_ptr<Ciphertext<Element>> KeySwitch(
				const shared_ptr<LPEvalKey<Element>> keySwitchHint,
				const shared_ptr<Ciphertext<Element>> cipherText) const = 0;

			/**
			* Virtual function to define the interface for generating a evaluation key which is used after each multiplication.
			*
			* @param &ciphertext1 first input ciphertext.
			* @param &ciphertext2 second input ciphertext.
			* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
			* @param *newCiphertext the new resulting ciphertext.
			*/
			virtual	shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(
					const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const = 0;		

			/**
			 * Virtual function to define the interface for evaluating ciphertext at an index
			 *
			 * @param &ciphertext the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */
			virtual shared_ptr<Ciphertext<Element>> EvalAtIndex(const shared_ptr<Ciphertext<Element>> ciphertext, const usint i,
					const std::vector<shared_ptr<LPEvalKey<Element>>> &evalKeys) const = 0;

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
				std::vector<shared_ptr<LPEvalKey<Element>>> *evalKeys) const = 0;
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
	 * @brief main implementation class to capture essential cryptoparameters of any LBC system
	 * @tparam Element a ring element.
	 */
	template <typename Element>
	class LPCryptoParameters : public Serializable
	{		
	public:
		virtual ~LPCryptoParameters() {}

		/**
			* Returns the value of plaintext modulus p
			*
			* @return the plaintext modulus.
			*/
		const BigBinaryInteger &GetPlaintextModulus() const { return  m_plaintextModulus; }

		/**
			* Returns the reference to IL params
			*
			* @return the ring element parameters.
			*/
		const shared_ptr<typename Element::Params> GetElementParams() const { return m_params; }
			
		/**
		* Sets the value of plaintext modulus p
		*/
		void SetPlaintextModulus(const BigBinaryInteger &plaintextModulus) { m_plaintextModulus = plaintextModulus; }
			
		virtual bool operator==(const LPCryptoParameters<Element>& cmp) const = 0;

		/**
		 * Sets the reference to element params
		 */
		void SetElementParams(shared_ptr<typename Element::Params> params) { m_params = params; }

		virtual const DiscreteGaussianGenerator& GetDiscreteGaussianGenerator() const {
			throw std::logic_error("These parameters do not use a DGG");
		}


	protected:
		LPCryptoParameters() : m_plaintextModulus(BigBinaryInteger::TWO) {}

		LPCryptoParameters(const BigBinaryInteger &plaintextModulus) : m_plaintextModulus(plaintextModulus) {}

		LPCryptoParameters(shared_ptr<typename Element::Params> params, const BigBinaryInteger &plaintextModulus) : m_plaintextModulus(plaintextModulus) {
			m_params = params;
		}

		LPCryptoParameters(LPCryptoParameters<Element> *from, shared_ptr<typename Element::Params> newElemParms) {
			*this = *from;
			m_params = newElemParms;
		}

	private:
		//element-specific parameters
		shared_ptr<typename Element::Params>	m_params;

		//plaintext modulus p
		BigBinaryInteger		m_plaintextModulus;
	};

	
	/**
	 * @brief Abstract interface for public key encryption schemes
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyEncryptionScheme {

	public:
		LPPublicKeyEncryptionScheme() :
			m_algorithmParamsGen(0), m_algorithmEncryption(0), m_algorithmPRE(0),
			m_algorithmSHE(0), m_algorithmFHE(0), m_algorithmLeveledSHE(0) {}

		virtual ~LPPublicKeyEncryptionScheme() {
			if (this->m_algorithmParamsGen != NULL)
				delete this->m_algorithmParamsGen;
			if (this->m_algorithmEncryption != NULL)
				delete this->m_algorithmEncryption;
			if (this->m_algorithmPRE != NULL)
				delete this->m_algorithmPRE;
			if (this->m_algorithmSHE != NULL)
				delete this->m_algorithmSHE;
			if (this->m_algorithmFHE != NULL)
				delete this->m_algorithmFHE;
			if (this->m_algorithmLeveledSHE != NULL)
				delete this->m_algorithmLeveledSHE;
		}
		
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

		/////////////////////////////////////////
		// wrapper for LPParameterSelectionAlgorithm
		//

		bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const {
			if (this->m_algorithmParamsGen) {
				return this->m_algorithmParamsGen->ParamsGen(cryptoParams, evalAddCount, evalMultCount, keySwitchCount);
			}
			else {
				throw std::logic_error("Parameter generation operation has not been implemented");
			}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPEncryptionAlgorithm (ENCRYPT)
		//

		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
			Element &plaintext) const {
				if(this->m_algorithmEncryption) {
					return this->m_algorithmEncryption->Encrypt(publicKey,plaintext);
				}
				else {
					throw std::logic_error("Encrypt operation has not been enabled");
				}
		}

		DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey, const shared_ptr<Ciphertext<Element>> ciphertext,
				Element *plaintext) const {
				if(this->m_algorithmEncryption)
					return this->m_algorithmEncryption->Decrypt(privateKey,ciphertext,plaintext);
				else {
					throw std::logic_error("Decrypt operation has not been enabled");
				}
		}

		LPKeyPair<Element> KeyGen(const CryptoContext<Element> cc, bool makeSparse) const {
				if(this->m_algorithmEncryption)
					return this->m_algorithmEncryption->KeyGen(cc, makeSparse);
				else {
					throw std::logic_error("KeyGen operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the two functions below are wrappers for things in LPPREAlgorithm (PRE)
		//

		shared_ptr<LPEvalKey<Element>> ReKeyGen(const shared_ptr<LPKey<Element>> newKey, const shared_ptr<LPPrivateKey<Element>> origPrivateKey) const{
				if(this->m_algorithmPRE)
					return this->m_algorithmPRE->ReKeyGen(newKey,origPrivateKey);
				else {
					throw std::logic_error("ReKeyGen operation has not been enabled");
				}
		}

		//wrapper for ReEncrypt method
		shared_ptr<Ciphertext<Element>> ReEncrypt(const shared_ptr<LPEvalKey<Element>> evalKey,
				const shared_ptr<Ciphertext<Element>> ciphertext) const {
				if(this->m_algorithmPRE)
					return this->m_algorithmPRE->ReEncrypt(evalKey,ciphertext);
				else {
					throw std::logic_error("ReEncrypt operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		shared_ptr<Ciphertext<Element>> EvalAdd(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalAdd(ciphertext1, ciphertext2);
			else {
				throw std::logic_error("EvalAdd operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> EvalSub(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalSub(ciphertext1, ciphertext2);
			else {
				throw std::logic_error("EvalSub operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalMult(ciphertext1, ciphertext2);
			else {
				throw std::logic_error("EvalMult operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> EvalMult(const shared_ptr<Ciphertext<Element>> ciphertext1,
			const shared_ptr<Ciphertext<Element>> ciphertext2,
			const shared_ptr<LPEvalKey<Element>> evalKey) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalMult(ciphertext1, ciphertext2, evalKey);
			else {
				throw std::logic_error("EvalMult operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> EvalNegate(const shared_ptr<Ciphertext<Element>> ciphertext) const {

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalNegate(ciphertext);
			else {
				throw std::logic_error("EvalNegate operation has not been enabled");
			}
		}

		/**
		* EvalLinRegression - Computes the parameter vector for linear regression using the least squares method
		* @param x - matrix of regressors
		* @param y - vector of dependent variables
		* @return the parameter vector using (x^T x)^{-1} x^T y (using least squares method)
		*/
		shared_ptr<Matrix<RationalCiphertext<Element>>>
			EvalLinRegression(const shared_ptr<Matrix<RationalCiphertext<Element>>> x,
				const shared_ptr<Matrix<RationalCiphertext<Element>>> y) const
		{

			if (this->m_algorithmSHE)
				return this->m_algorithmSHE->EvalLinRegression(x, y);
			else {
				throw std::logic_error("EvalLinRegression operation has not been enabled");
			}

		}

		shared_ptr<LPEvalKey<Element>> KeySwitchGen(
			const shared_ptr<LPPrivateKey<Element>> originalPrivateKey,
			const shared_ptr<LPPrivateKey<Element>> newPrivateKey) const {
			if (this->m_algorithmSHE)
				return  this->m_algorithmSHE->KeySwitchGen(originalPrivateKey, newPrivateKey);
			else {
				throw std::logic_error("KeySwitchGen operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> KeySwitch(
			const shared_ptr<LPEvalKey<Element>> keySwitchHint,
			const shared_ptr<Ciphertext<Element>> cipherText) const {

			if (this->m_algorithmSHE) {
				return this->m_algorithmSHE->KeySwitch(keySwitchHint, cipherText);
			}
			else {
				throw std::logic_error("KeySwitch operation has not been enabled");
			}
		}

		shared_ptr<LPEvalKey<Element>> EvalMultKeyGen(const shared_ptr<LPPrivateKey<Element>> originalPrivateKey) const {
				if(this->m_algorithmSHE)
					return this->m_algorithmSHE->EvalMultKeyGen(originalPrivateKey);
				else {
					throw std::logic_error("EvalMultKeyGen operation has not been enabled");
				}
		}

		
		/////////////////////////////////////////
		// the functions below are wrappers for things in LPFHEAlgorithm (FHE)
		//
		// TODO: Add Functions?

		/////////////////////////////////////////
		// the functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		shared_ptr<Ciphertext<Element>> ModReduce(shared_ptr<Ciphertext<Element>> cipherText) const {
			if(this->m_algorithmLeveledSHE){
				return this->m_algorithmLeveledSHE->ModReduce(cipherText);
			}
			else{
				throw std::logic_error("ModReduce operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> RingReduce(shared_ptr<Ciphertext<Element>> cipherText, const shared_ptr<LPEvalKey<Element>> keySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				return this->m_algorithmLeveledSHE->RingReduce(cipherText,keySwitchHint);
			}
			else{
				throw std::logic_error("RingReduce operation has not been enabled");
			}
		}

		bool CanRingReduce(usint ringDimension, const std::vector<BigBinaryInteger> &moduli, const double rootHermiteFactor) const {
			if (this->m_algorithmLeveledSHE) {
				return this->m_algorithmLeveledSHE->CanRingReduce(ringDimension, moduli, rootHermiteFactor);
			}
			else {
				throw std::logic_error("CanRingReduce operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> ComposedEvalMult(
							const shared_ptr<Ciphertext<Element>> cipherText1,
							const shared_ptr<Ciphertext<Element>> cipherText2,
							const shared_ptr<LPEvalKey<Element>> quadKeySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				return this->m_algorithmLeveledSHE->ComposedEvalMult(cipherText1,cipherText2,quadKeySwitchHint);
			}
			else{
				throw std::logic_error("ComposedEvalMult operation has not been enabled");
			}
		}

		shared_ptr<Ciphertext<Element>> LevelReduce(const shared_ptr<Ciphertext<Element>> cipherText1,
				const shared_ptr<LPEvalKeyNTRU<Element>> linearKeySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				this->m_algorithmLeveledSHE->LevelReduce(cipherText1,linearKeySwitchHint);
			}
			else{
				throw std::logic_error("LevelReduce operation has not been enabled");
			}
		}

		const LPEncryptionAlgorithm<Element>& getAlgorithm() const { return *m_algorithmEncryption; }

	protected:
		const LPParameterGenerationAlgorithm<Element> *m_algorithmParamsGen;
		const LPEncryptionAlgorithm<Element> *m_algorithmEncryption;
		const LPPREAlgorithm<Element> *m_algorithmPRE;
		const LPSHEAlgorithm<Element> *m_algorithmSHE;
		const LPFHEAlgorithm<Element> *m_algorithmFHE;
		const LPLeveledSHEAlgorithm<Element> *m_algorithmLeveledSHE;
	};

} // namespace lbcrypto ends
#endif