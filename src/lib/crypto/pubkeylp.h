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
#include "../utils/serializablehelper.h"


/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	//forward declaration of Ciphertext class; used to resolve circular header dependency
	template <class Element>
	class Ciphertext;

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

	//declaration of DeserializeCryptoParameters function;
	template <typename Element>
	inline LPCryptoParameters<Element>* DeserializeCryptoParameters(const Serialized &serObj);

	//declaration of DeserializeAndValidateCryptoParameters function;
	template <typename Element>
	inline LPCryptoParameters<Element>* DeserializeAndValidateCryptoParameters(const Serialized& serObj, const LPCryptoParameters<Element>& curP);


	/*template <class Element>
	class LPEvalKeyNTRU;*/

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

		LPKey(LPCryptoParameters<Element> *cp = 0) : m_cryptoParameters(cp) {}

		virtual ~LPKey() {}

		/**
		 * Gets a read-only reference to an LPCryptoParameters-derived class
		 * @return the crypto parameters.
		 */
		const LPCryptoParameters<Element> &GetCryptoParameters() const { return *m_cryptoParameters; }

	protected:
		LPCryptoParameters<Element> *m_cryptoParameters;
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
			LPPublicKey(LPCryptoParameters<Element> &cryptoParams) : LPKey<Element>(&cryptoParams) {}

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
			bool Serialize(Serialized *serObj, const std::string fileFlag = "") const {
				serObj->SetObject();

				if (!this->GetCryptoParameters().Serialize(serObj, "")) {
					return false;
				}

				const Element& pe = this->GetPublicElements().at(0);

				if (!pe.Serialize(serObj, "")) {
					return false;
				}

				if (!this->SetIdFlag(serObj, fileFlag))
					return false;

				return true;
			}

			/**
			* Higher level info about the serialization is saved here
			* @param *serObj to store the the implementing object's serialization specific attributes.
			* @param flag an object-specific parameter for the serialization
			* @return true on success
			*/
			bool SetIdFlag(Serialized *serObj, const std::string flag) const {

				SerialItem idFlagMap(rapidjson::kObjectType);
				idFlagMap.AddMember("ID", "LPPublicKey", serObj->GetAllocator());
				idFlagMap.AddMember("Flag", flag, serObj->GetAllocator());
				serObj->AddMember("Root", idFlagMap, serObj->GetAllocator());

				return true;
			}

			/**
			* Populate the object from the deserialization of the Serialized
			* @param &serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized &serObj) { 
				return false;
			}

			/**
			* Populate the object from the deserialization of the Serialized
			* @param &serObj contains the serialized object
			* @param *ctx
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj, const CryptoContext<Element> *ctx) { //TODO: @Gerard Ryan, complete doxygen documentation

				LPCryptoParameters<Element>* cryptoParams = DeserializeAndValidateCryptoParameters<Element>(serObj, *ctx->getParams());
				if (cryptoParams == 0) return false;

				this->m_cryptoParameters = cryptoParams;

				Element json_ilElement;
				if (json_ilElement.Deserialize(serObj)) {
					this->SetPublicElementAtIndex(0,json_ilElement);
					return true;
				}

				return false;
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

		LPEvalKey(LPCryptoParameters<Element> &cryptoParams) : LPKey<Element>(&cryptoParams) {}

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
		LPEvalKeyRelin(LPCryptoParameters<Element> &cryptoParams) : LPEvalKey<Element>(cryptoParams) {}

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
		* Higher level info about the serialization is saved here
		* @param *serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized *serObj, const std::string flag) const {

			SerialItem idFlagMap(rapidjson::kObjectType);
			idFlagMap.AddMember("ID", "LPEvalKeyRelin", serObj->GetAllocator());
			idFlagMap.AddMember("Flag", flag, serObj->GetAllocator());
			serObj->AddMember("Root", idFlagMap, serObj->GetAllocator());

			return true;
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj, const std::string fileFlag = "") const {
			serObj->SetObject();

			if (!this->GetCryptoParameters().Serialize(serObj, "")) {
				return false;
			}

			std::cout << "element count " << m_rKey.size() << std::endl;

			SerializeVector<Element>("AVector", typeid(Element).name(), this->GetAVector(), serObj);
			SerializeVector<Element>("BVector", typeid(Element).name(), this->GetBVector(), serObj);

//			const Element& pe = this->GetA();
//
//			if (!pe.Serialize(serObj, "")) {
//				return false;
//			}
//
			if (!this->SetIdFlag(serObj, fileFlag))
				return false;

			return true;
		}

		/**
		* Populate the object from the deserialization of the Serialized
		* @param &serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj, const CryptoContext<Element> *ctx) {
			LPCryptoParameters<Element>* cryptoparams = DeserializeAndValidateCryptoParameters<Element>(serObj, *ctx->getParams());
			if (cryptoparams == 0) return false;

			this->m_cryptoParameters = cryptoparams;

//			DeSerializeVector<Element>("AVector", typeid(Element).name(), this->GetAVector(), serObj);
//			DeSerializeVector<Element>("BVector", typeid(Element).name(), this->GetBVector(), serObj);

//			Element json_ilelement;
//			if (json_ilelement.deserialize(serObj)) {
//				this->SetA(json_ilelement);
//				return true;
//			}

			return false;
		}

		bool Deserialize(const Serialized &serObj) {
			return false;
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

		LPEvalKeyNTRURelin(LPCryptoParameters<Element> &cryptoParams) : LPEvalKey<Element>(cryptoParams) {}

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
		* Higher level info about the serialization is saved here
		* @param *serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized *serObj, const std::string flag) const {

			SerialItem idFlagMap(rapidjson::kObjectType);
			idFlagMap.AddMember("ID", "LPEvalKeyNTRURelin", serObj->GetAllocator());
			idFlagMap.AddMember("Flag", flag, serObj->GetAllocator());
			serObj->AddMember("Root", idFlagMap, serObj->GetAllocator());

			return true;
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj, const std::string fileFlag = "") const {
			serObj->SetObject();

			if (!this->GetCryptoParameters().Serialize(serObj, "")) {
				return false;
			}

			SerializeVector<Element>("Vectors", "ILVector2n", this->GetAVector(), serObj);

			if (!this->SetIdFlag(serObj, fileFlag))
				return false;

			return true;
		}

		/**
		* Populate the object from the deserialization of the Serialized
		* @param &serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj, const CryptoContext<Element> *ctx) {
			LPCryptoParameters<Element>* cryptoparams = DeserializeAndValidateCryptoParameters<Element>(serObj, *ctx->getParams());
			if (cryptoparams == 0) return false;

			this->m_cryptoParameters = cryptoparams;

			SerialItem::ConstMemberIterator it = serObj.FindMember("Vectors");

			if( it == serObj.MemberEnd() ) {
				return false;
			}

			std::vector<Element> newElements;
			if( DeserializeVector<Element>("Vectors", "ILVector2n", it, &newElements) ) {
				this->SetAVector(newElements);
				return true;
			}

			return false;
		}

		bool Deserialize(const Serialized &serObj) {
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

		LPEvalKeyNTRU(LPCryptoParameters<Element> &cryptoParams) : LPEvalKey<Element>(cryptoParams) {}

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
		* Higher level info about the serialization is saved here
		* @param *serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized *serObj, const std::string flag) const {

			SerialItem idFlagMap(rapidjson::kObjectType);
			idFlagMap.AddMember("ID", "LPEvalKeyNTRU", serObj->GetAllocator());
			idFlagMap.AddMember("Flag", flag, serObj->GetAllocator());
			serObj->AddMember("Root", idFlagMap, serObj->GetAllocator());

			return true;
		}

		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj, const std::string fileFlag = "") const {
			serObj->SetObject();

			if (!this->GetCryptoParameters().Serialize(serObj, "")) {
				return false;
			}

			const Element& pe = this->GetA();

			if (!pe.Serialize(serObj, "")) {
				return false;
			}

			if (!this->SetIdFlag(serObj, fileFlag))
				return false;

			return true;
		}

		/**
		* Populate the object from the deserialization of the Serialized
		* @param &serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj, const CryptoContext<Element> *ctx) {
			LPCryptoParameters<Element>* cryptoparams = DeserializeAndValidateCryptoParameters<Element>(serObj, *ctx->getparams());
			if (cryptoparams == 0) return false;

			this->m_cryptoParameters = cryptoparams;

			Element json_ilelement;
			if (json_ilelement.deserialize(serObj)) {
				this->SetA(json_ilelement);
				return true;
			}

			return false;
		}

		bool Deserialize(const Serialized &serObj) {
			return false;
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

		LPPrivateKey(LPCryptoParameters<Element> &cryptoParams) : LPKey<Element>(&cryptoParams) {}

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

		//JSON FACILITY
		/**
		* Serialize the object into a Serialized
		* @param *serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @param fileFlag is an object-specific parameter for the serialization
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized *serObj, const std::string fileFlag = "") const {

			serObj->SetObject();
			if (!this->SetIdFlag(serObj, fileFlag))
				return false;

			if (!this->GetCryptoParameters().Serialize(serObj))
				return false;

			return this->GetPrivateElement().Serialize(serObj);
		}

		/**
		* Higher level info about the serialization is saved here
		* @param *serObj to store the the implementing object's serialization specific attributes.
		* @param flag an object-specific parameter for the serialization
		* @return true on success
		*/
		bool SetIdFlag(Serialized *serObj, const std::string flag) const {
			SerialItem idFlagMap(rapidjson::kObjectType);
			idFlagMap.AddMember("ID", "LPPrivateKey", serObj->GetAllocator());
			idFlagMap.AddMember("Flag", flag, serObj->GetAllocator());
			serObj->AddMember("Root", idFlagMap, serObj->GetAllocator());

			return true;
		}

		/**
		* Populate the object from the deserialization of the Setialized
		* @param &serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj) { 
			return false;
		}

		/**
		* Populate the object from the deserialization of the Setialized
		* @param &serObj contains the serialized object
		* @param *ctx
		* @return true on success
		*/
		bool Deserialize(const Serialized &serObj, const CryptoContext<Element> *ctx) {
			LPCryptoParameters<Element>* cryptoParams = DeserializeAndValidateCryptoParameters<Element>(serObj, *ctx->getParams());
			if (cryptoParams == 0) return false;

			this->m_cryptoParameters = cryptoParams;

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
			virtual EncryptResult Encrypt(const LPPublicKey<Element> &publicKey,
				const Element &plaintext,
				Ciphertext<Element> *ciphertext) const = 0;

			/**
			 * Method for decrypting plaintext using LBC
			 *
			 * @param &privateKey private key used for decryption.
			 * @param &ciphertext ciphertext id decrypted.
			 * @param *plaintext the plaintext output.
			 * @return the decoding result.
			 */
			virtual DecryptResult Decrypt(const LPPrivateKey<Element> &privateKey, 
				const Ciphertext<Element> &ciphertext,
				Element *plaintext) const = 0;

			/**
			 * Function to generate public and private keys
			 *
			 * @param &publicKey private key used for decryption.
			 * @param &privateKey private key used for decryption.
			 * @return function ran correctly.
			 */
			virtual bool KeyGen(LPPublicKey<Element> *publicKey, 
				LPPrivateKey<Element> *privateKey) const = 0;

	};


	/**
	 * @brief Abstract interface for Leveled SHE operations
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPLeveledSHEAlgorithm {
		public:	

			/**
			 * Method for EvalMultKeyGen
			 *
			 * @param &originalPrivateKey Original private key used for encryption.
			 * @param &newPrivateKey New private key to generate the keyswitch hint.
			 * @param *KeySwitchHint is where the resulting keySwitchHint will be placed.
			 */
			virtual void EvalMultKeyGen(const LPPrivateKey<Element> &originalPrivateKey, 
				const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *keySwitchHint) const = 0;
			
			/**
			 * Method for KeySwitch
			 *
			 * @param &keySwitchHint Hint required to perform the ciphertext switching.
			 * @param &cipherText Original ciphertext to perform switching on.
			 */
			virtual Ciphertext<Element> KeySwitch(const LPEvalKey<Element> &keySwitchHint, const Ciphertext<Element> &cipherText) const = 0;

			/**
			 * Method for generating a keyswitchhint from originalPrivateKey square to newPrivateKey
			 *
			 * @param &originalPrivateKey that is (in method) squared for the keyswitchhint.
			 * @param &newPrivateKey new private for generating a keyswitchhint to.
			 * @param *quadraticKeySwitchHint the generated keyswitchhint.
			 */

			virtual void QuadraticEvalMultKeyGen(const LPPrivateKey<Element> &originalPrivateKey, const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *quadraticKeySwitchHint) const = 0;

			/**
			 * Method for Modulus Reduction.
			 *
			 * @param &cipherText Ciphertext to perform mod reduce on.
			 */
			virtual void ModReduce(Ciphertext<Element> *cipherText) const = 0; 

			/**
			 * Method for Ring Reduction.
			 *
			 * @param &cipherText Ciphertext to perform ring reduce on.
			 * @param &privateKey Private key used to encrypt the first argument.
			 */
			virtual void RingReduce(Ciphertext<Element> *cipherText, const LPEvalKeyNTRU<Element> &keySwitchHint) const = 0; 

			/**
			 * Method for Composed EvalMult
			 *
			 * @param &cipherText1 ciphertext1, first input ciphertext to perform multiplication on.
			 * @param &cipherText2 cipherText2, second input ciphertext to perform multiplication on.
			 * @param &quadKeySwitchHint is for resultant quadratic secret key after multiplication to the secret key of the particular level.
			 * @param &cipherTextResult is the resulting ciphertext that can be decrypted with the secret key of the particular level.
			 */
			virtual void ComposedEvalMult(const Ciphertext<Element> &cipherText1, const Ciphertext<Element> &cipherText2, const LPEvalKeyNTRU<Element> &quadKeySwitchHint, Ciphertext<Element> *cipherTextResult) const = 0;

			/**
			 * Method for Level Reduction from sk -> sk1. This method peforms a keyswitch on the ciphertext and then performs a modulus reduction.
			 *
			 * @param &cipherText1 is the original ciphertext to be key switched and mod reduced.
			 * @param &linearKeySwitchHint is the linear key switch hint to perform the key switch operation.
			 * @param &cipherTextResult is the resulting ciphertext.
			 */
			virtual void LevelReduce(const Ciphertext<Element> &cipherText1, const LPEvalKeyNTRU<Element> &linearKeySwitchHint, Ciphertext<Element> *cipherTextResult) const = 0;
			/**
			* Function to generate sparse public and private keys. By sparse it is meant that all even indices are non-zero
			* and odd indices are set to zero.
			*
			* @param *publicKey is the public key to be generated.
			* @param *privateKey is the private key to be generated.
			*/
			virtual bool SparseKeyGen(LPPublicKey<Element> *publicKey, LPPrivateKey<Element> *privateKey) const = 0;
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
			virtual bool ReKeyGen(const LPKey<Element> &newKey, 
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
			 * Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext.
			 *
			 * @param &ciphertext1 the input ciphertext.
			 * @param &ciphertext2 the input ciphertext.
			 * @param *newCiphertext the new ciphertext.
			 */

			virtual	bool RelinKeyGen(const LPPrivateKey<Element> &privateKey,
			LPEvalKey<Element> *evalKey) const = 0;

			virtual void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const = 0;

			virtual void EvalAdd(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const = 0;

			/**
			* Virtual function to define the interface for multiplicative homomorphic evaluation of ciphertext using the evaluation key.
			*
			* @param &ciphertext1 first input ciphertext.
			* @param &ciphertext2 second input ciphertext.
			* @param &ek is the evaluation key to make the newCiphertext decryptable by the same secret key as that of ciphertext1 and ciphertext2.
			* @param *newCiphertext the new resulting ciphertext.
			*/
			virtual void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2, const LPEvalKey<Element> &ek,
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
		const ElemParams &GetElementParams() const { return *m_params; }
			
		/**
		* Sets the value of plaintext modulus p
		*/
		void SetPlaintextModulus(const BigBinaryInteger &plaintextModulus) { m_plaintextModulus = plaintextModulus; }
			
		/**
			* Sets the reference to element params
			*/
		void SetElementParams(ElemParams &params) { m_params = &params; }

		virtual bool operator==(const LPCryptoParameters<Element>& cmp) const = 0;

	protected:
		LPCryptoParameters() : m_params(NULL), m_plaintextModulus(BigBinaryInteger::TWO) {}

		LPCryptoParameters(ElemParams *params, const BigBinaryInteger &plaintextModulus) : m_params(params), m_plaintextModulus(plaintextModulus) {}

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
	class LPPublicKeyEncryptionScheme {

	public:
		LPPublicKeyEncryptionScheme() :
			m_algorithmEncryption(0), m_algorithmPRE(0), m_algorithmEvalAdd(0), m_algorithmEvalAutomorphism(0),
			m_algorithmSHE(0), m_algorithmFHE(0), m_algorithmLeveledSHE(0) {}

		virtual ~LPPublicKeyEncryptionScheme() {
			if (this->m_algorithmEncryption != NULL)
				delete this->m_algorithmEncryption;
			if (this->m_algorithmPRE != NULL)
				delete this->m_algorithmPRE;
			if (this->m_algorithmEvalAdd != NULL)
				delete this->m_algorithmEvalAdd;
			if (this->m_algorithmEvalAutomorphism != NULL)
				delete this->m_algorithmEvalAutomorphism;
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

		/////////////////////////////////////////
		// the three functions below are wrappers for things in LPEncryptionAlgorithm (ENCRYPT)
		//

		EncryptResult Encrypt(const LPPublicKey<Element> &publicKey,
			const Element &plaintext, Ciphertext<Element> *ciphertext) const {
				if(this->m_algorithmEncryption) {
					return this->m_algorithmEncryption->Encrypt(publicKey,plaintext,ciphertext);
				}
				else {
					throw std::logic_error("Encrypt operation has not been enabled");
				}
		}

		DecryptResult Decrypt(const LPPrivateKey<Element> &privateKey, const Ciphertext<Element> &ciphertext,
				Element *plaintext) const {
				if(this->m_algorithmEncryption)
					return this->m_algorithmEncryption->Decrypt(privateKey,ciphertext,plaintext);
				else {
					throw std::logic_error("Decrypt operation has not been enabled");
				}
		}

		bool KeyGen(LPPublicKey<Element> *publicKey, LPPrivateKey<Element> *privateKey) const {
				if(this->m_algorithmEncryption)
					return this->m_algorithmEncryption->KeyGen(publicKey,privateKey);
				else {
					throw std::logic_error("KeyGen operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the two functions below are wrappers for things in LPPREAlgorithm (PRE)
		//

		bool ReKeyGen(const LPKey<Element> &newKey, const LPPrivateKey<Element> &origPrivateKey,
			LPEvalKey<Element> *evalKey) const{
				if(this->m_algorithmPRE)
					return this->m_algorithmPRE->ReKeyGen(newKey,origPrivateKey,evalKey);
				else {
					throw std::logic_error("ReKeyGen operation has not been enabled");
				}
		}

		//wrapper for reLinKeyGen method
		bool RelinKeyGen(const LPPrivateKey<Element> &privateKey,
			LPEvalKey<Element> *evalKey) const{
				if(this->IsEnabled(SHE))
					return this->m_algorithmSHE->RelinKeyGen(privateKey,evalKey);
				else {
					throw std::logic_error("This operation is not supported");
				}
		}

		//wrapper for ReEncrypt method
		void ReEncrypt(const LPEvalKey<Element> &evalKey, const Ciphertext<Element> &ciphertext,
			Ciphertext<Element> *newCiphertext) const {
				if(this->m_algorithmPRE)
					this->m_algorithmPRE->ReEncrypt(evalKey,ciphertext,newCiphertext);
				else {
					throw std::logic_error("ReEncrypt operation has not been enabled");
				}
		}

		/////////////////////////////////////////
		// the functions below are wrappers for things in LPAHEAlgorithm (EVALADD)
		//
		// TODO: Add Functions?

		/////////////////////////////////////////
		// the function below is a wrapper for things in LPAutomorphAlgorithm (EVALAUTOMORPHISM)
		//
		// TODO: Add Functions?

		const LPAutoMorphAlgorithm<Element> &GetLPAutoMorphAlgorithm() {
			if(this->m_algorithmEvalAutomorphism)
				return *m_algorithmEvalAutomorphism;
			else
				throw std::logic_error("Automorphism has not been enabled");
		}

		/////////////////////////////////////////
		// the two functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		void EvalAdd(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const {

					if(this->m_algorithmSHE)
						this->m_algorithmSHE->EvalAdd(ciphertext1,ciphertext2,newCiphertext);
					else{
						throw std::logic_error("EvalAdd operation has not been enabled");
					}
		}

		void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2,
				Ciphertext<Element> *newCiphertext) const {
					
					if(this->m_algorithmSHE)
						this->m_algorithmSHE->EvalMult(ciphertext1,ciphertext2,newCiphertext);
					else{
						throw std::logic_error("EvalMult operation has not been enabled");
					}
		}




		/////////////////////////////////////////
		// the functions below are wrappers for things in LPFHEAlgorithm (FHE)
		//
		// TODO: Add Functions?

		/////////////////////////////////////////
		// the nine functions below are wrappers for things in LPSHEAlgorithm (SHE)
		//

		bool SparseKeyGen(LPPublicKey<Element> *publicKey,
		        	LPPrivateKey<Element> *privateKey) const {
				if(this->m_algorithmLeveledSHE)
					return this->m_algorithmLeveledSHE->SparseKeyGen(publicKey, privateKey);
				else {
					throw std::logic_error("SparseKeyGen operation has not been enabled");
				}
		}

		//wrapper for EvalMult method
		void EvalMult(const Ciphertext<Element> &ciphertext1,
				const Ciphertext<Element> &ciphertext2, const LPEvalKey<Element> &evalKey,
				Ciphertext<Element> *newCiphertext) const {
					
					if(this->IsEnabled(SHE))
						this->m_algorithmSHE->EvalMult(ciphertext1,ciphertext2, evalKey, newCiphertext);
					else{
						throw std::logic_error("This operation is not supported");
					}
		}

		void EvalMultKeyGen(const LPPrivateKey<Element> &originalPrivateKey, 
				const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *keySwitchHint) const {
					if(this->m_algorithmLeveledSHE)
						this->m_algorithmLeveledSHE->EvalMultKeyGen(originalPrivateKey, newPrivateKey,keySwitchHint);
					else{
						throw std::logic_error("EvalMultKeyGen operation has not been enabled");
					}
		}

		Ciphertext<Element> KeySwitch(const LPEvalKey<Element> &keySwitchHint, const Ciphertext<Element> &cipherText) const {
			
			if(this->m_algorithmLeveledSHE){
				return this->m_algorithmLeveledSHE->KeySwitch(keySwitchHint,cipherText);
			}
			else{
				throw std::logic_error("KeySwitch operation has not been enabled");
			}
		}

		void QuadraticEvalMultKeyGen(const LPPrivateKey<Element> &originalPrivateKey, const LPPrivateKey<Element> &newPrivateKey, LPEvalKeyNTRU<Element> *quadraticKeySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				this->m_algorithmLeveledSHE->QuadraticEvalMultKeyGen(originalPrivateKey,newPrivateKey,quadraticKeySwitchHint);
			}
			else{
				throw std::logic_error("QuadraticEvalMultKeyGen operation has not been enabled");
			}
		}

		void ModReduce(Ciphertext<Element> *cipherText) const {
			if(this->m_algorithmLeveledSHE){
				this->m_algorithmLeveledSHE->ModReduce(cipherText);
			}
			else{
				throw std::logic_error("ModReduce operation has not been enabled");
			}
		}

		void RingReduce(Ciphertext<Element> *cipherText, const LPEvalKeyNTRU<Element> &keySwitchHint) const {
			if(this->m_algorithmLeveledSHE){
				this->m_algorithmLeveledSHE->RingReduce(cipherText,keySwitchHint);
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

		void ComposedEvalMult(const Ciphertext<Element> &cipherText1, const Ciphertext<Element> &cipherText2, const LPEvalKeyNTRU<Element> &quadKeySwitchHint, Ciphertext<Element> *cipherTextResult) const {
			if(this->m_algorithmLeveledSHE){
				this->m_algorithmLeveledSHE->ComposedEvalMult(cipherText1,cipherText2,quadKeySwitchHint,cipherTextResult);
			}
			else{
				throw std::logic_error("ComposedEvalMult operation has not been enabled");
			}
		}

		void LevelReduce(const Ciphertext<Element> &cipherText1, const LPEvalKeyNTRU<Element> &linearKeySwitchHint, Ciphertext<Element> *cipherTextResult) const {
			if(this->m_algorithmLeveledSHE){
				this->m_algorithmLeveledSHE->LevelReduce(cipherText1,linearKeySwitchHint,cipherTextResult);
			}
			else{
				throw std::logic_error("LevelReduce operation has not been enabled");
			}
		}

		const LPEncryptionAlgorithm<Element>& getAlgorithm() const { return *m_algorithmEncryption; }

	protected:
		const LPEncryptionAlgorithm<Element> *m_algorithmEncryption;
		const LPPREAlgorithm<Element> *m_algorithmPRE;
		const LPAHEAlgorithm<Element> *m_algorithmEvalAdd;
		const LPAutoMorphAlgorithm<Element> *m_algorithmEvalAutomorphism;
		const LPSHEAlgorithm<Element> *m_algorithmSHE;
		const LPFHEAlgorithm<Element> *m_algorithmFHE;
		const LPLeveledSHEAlgorithm<Element> *m_algorithmLeveledSHE;
	};


	/**
	 * @brief main implementation class for public key encryption algorithms
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPPublicKeyEncryptionAlgorithmImpl
	{		
	public:
		//@Get Properties
		/**
		* Getter method for a refernce to the scheme
		*
		*@return the refernce to the scheme.
		*/
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

	/** This function is used to deserialize the Crypto Parameters
	*
	* @param &serObj object to be serialized
	*
	* @return the parameters or null on failure
	*/
	template <typename Element>
	inline LPCryptoParameters<Element>* DeserializeCryptoParameters(const Serialized &serObj)
	{
		LPCryptoParameters<Element>* parmPtr = 0;

		Serialized::ConstMemberIterator it = serObj.FindMember("LPCryptoParametersType");
		if (it == serObj.MemberEnd()) return 0;
		std::string type = it->value.GetString();

		if (type == "LPCryptoParametersLTV") {
			parmPtr = new LPCryptoParametersLTV<Element>();
		}
		else if (type == "LPCryptoParametersStehleSteinfeld") {
			parmPtr = new LPCryptoParametersStehleSteinfeld<Element>();
		}
		else if (type == "LPCryptoParametersBV") {
			parmPtr = new LPCryptoParametersBV<Element>();
		}
		else
			return 0;

		if (!parmPtr->Deserialize(serObj)) {
			delete parmPtr;
			return 0;
		}

		return parmPtr;
	}

	/** This function is used to deserialize the Crypto Parameters, to compare them to the existing parameters,
	* and to fail if they do not match
	*
	* @param &serObj object to be desrialized
	* @param &curP LPCryptoParameters to validate against
	*
	* @return the parameters or null on failure
	*/
	template <typename Element>
	inline LPCryptoParameters<Element>* DeserializeAndValidateCryptoParameters(const Serialized& serObj, const LPCryptoParameters<Element>& curP)
	{
		LPCryptoParameters<Element>* parmPtr = DeserializeCryptoParameters<Element>(serObj);

		if (parmPtr == 0) return 0;

		// make sure the deserialized parms match the ones in the current context
		if (*parmPtr == curP)
			return parmPtr;

		delete parmPtr;
		return 0;
	}


} // namespace lbcrypto ends
#endif
