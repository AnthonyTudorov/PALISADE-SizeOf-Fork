/**
 * @file ciphertext.h -- Operations for the reoresentation of ciphertext in PALISADE.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */

#ifndef LBCRYPTO_CRYPTO_CIPHERTEXT_H
#define LBCRYPTO_CRYPTO_CIPHERTEXT_H

//Includes Section
#include "palisade.h"

namespace lbcrypto {

	/**
	* @brief Ciphertext
	*
	* The Ciphertext object is used to contain encrypted text in the PALISADE library
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class Ciphertext : public CryptoObject<Element> {
	public:

		/**
		* Default constructor
		*/
		Ciphertext() : CryptoObject<Element>(), m_depth(1), encodingType(Unknown) {}

		/**
		 * Construct a new ciphertext in the given context
		 *
		 * @param cc
		 */
		Ciphertext(shared_ptr<CryptoContext<Element>> cc, const string& id = "") :
			CryptoObject<Element>(cc.get(), id), m_depth(1), encodingType(Unknown) {}

		/**
		 * Construct a new ciphertext from the parameters of a given public key
		 *
		 * @param k key whose CryptoObject parameters will get cloned
		 */
		Ciphertext(const shared_ptr<LPKey<Element>> k) :
			CryptoObject<Element>(k->GetCryptoContext(), k->GetKeyTag()), m_depth(1), encodingType(Unknown)  {}

		/**
		* Copy constructor
		*/
		Ciphertext(const Ciphertext<Element> &ciphertext) : CryptoObject<Element>(ciphertext) {
			m_elements = ciphertext.m_elements;
			m_depth = ciphertext.m_depth;
			encodingType = ciphertext.encodingType;
		}

		/**
		* Move constructor
		*/
		Ciphertext(Ciphertext<Element> &&ciphertext) : CryptoObject<Element>(ciphertext) {
			m_elements = std::move(ciphertext.m_elements);
			m_depth = std::move(ciphertext.m_depth);
			encodingType = std::move(ciphertext.encodingType);
		}

		/**
		* Destructor
		*/
		virtual ~Ciphertext() {}

		/**
		 * GetEncodingType
		 * @return how the Plaintext that this Ciphertext was created from was encoded
		 */
		PlaintextEncodings GetEncodingType() const { return encodingType; }

		/**
		 * SetEncodingType - after Encrypt, remember the Ciphertext's encoding type
		 * @param et
		 */
		void SetEncodingType(PlaintextEncodings et) { encodingType = et; }

		/**
		* Assignment Operator.
		*
		* @param &rhs the Ciphertext to assign from
		* @return this Ciphertext
		*/
		Ciphertext<Element>& operator=(const Ciphertext<Element> &rhs) {
			if (this != &rhs) {
				CryptoObject<Element>::operator=(rhs);
				this->m_elements = rhs.m_elements;
				this->m_depth = rhs.m_depth;
				this->encodingType = rhs.encodingType;
			}

			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs the Ciphertext to move from
		* @return this Ciphertext
		*/
		Ciphertext<Element>& operator=(Ciphertext<Element> &&rhs) {
			if (this != &rhs) {
				CryptoObject<Element>::operator=(rhs);
				this->m_elements = std::move(rhs.m_elements);
				this->m_depth = std::move(rhs.m_depth);
				this->encodingType = std::move(rhs.encodingType);
			}

			return *this;
		}

		/**
		 * GetElement - get the ring element for the cases that use only one element in the vector
		 * this method will throw an exception if it's ever called in cases with other than 1 element
		 * @return the first (and only!) ring element
		 */
		const Element &GetElement() const {
			if (m_elements.size() == 1)
				return m_elements[0];
			else
			{
				throw std::logic_error("GetElement should only be used in cases with a Ciphertext with a single element");
			}
		}

		/**
		* GetElements: get all of the ring elements in the Ciphertext
		* @return vector of ring elements
		*/
		const std::vector<Element> &GetElements() const { return m_elements; }

		/**
		* SetElement - sets the ring element for the cases that use only one element in the vector
		* this method will throw an exception if it's ever called in cases with other than 1 element
		* @param &element is a polynomial ring element.
		*/
		void SetElement(const Element &element) {
			if (m_elements.size() == 0)
				m_elements.push_back(element);
			else if (m_elements.size() == 1)
				m_elements[0] = element;
			else
				throw std::logic_error("SetElement should only be used in cases with a Ciphertext with a single element");
		}

		/**
		* Sets the data elements.
		*
		* @param &element is a polynomial ring element.
		*/
		void SetElements(const std::vector<Element> &elements) { m_elements = elements; }

		/**
		* Sets the data elements by std::move.
		*
		* @param &&element is a polynomial ring element.
		*/
		void SetElements(const std::vector<Element> &&elements) { m_elements = std::move(elements); }

		/**
		* Get the depth of the ciphertext.
		* It will be used in multiplication/addition/subtraction to handle the keyswitching.
		*/
		const size_t GetDepth() const {
			return m_depth;
		}

		/**
		* Set the depth of the ciphertext.
		* It will be used in multiplication/addition/subtraction to handle the keyswitching.
		*/
		void SetDepth(size_t depth) {
			m_depth = depth;
		}

		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj) const;

		/**
		* Populate the object from the deserialization of the Serialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj);

		bool operator==(const Ciphertext<Element>& rhs) const {
			if( !CryptoObject<Element>::operator==(rhs) )
				return false;

			if( this->m_depth != rhs.m_depth || this->m_isEncrypted != rhs.m_isEncrypted )
				return false;

			const std::vector<Element> &lhsE = this->GetElements();
			const std::vector<Element> &rhsE = rhs.GetElements();

			if( lhsE.size() != rhsE.size() ) return false;

			for( size_t i=0; i<lhsE.size(); i++ ) {
				const Element& lE = lhsE.at(i);
				const Element& rE = rhsE.at(i);

				if( lE != rE ) return false;
			}

			return true;
		}

		bool operator!=(const Ciphertext<Element>& rhs) const {
			return ! (*this == rhs);
		}

		Ciphertext<Element> operator+(const Ciphertext<Element> &other) const {
			shared_ptr<Ciphertext<Element>> a(new Ciphertext<Element>(*this));
			shared_ptr<Ciphertext<Element>> b(new Ciphertext<Element>(other));
			return *this->GetCryptoContext()->EvalAdd(a, b);
		}

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &other is the ciphertext to add with.
		* @return the result of the addition.
		*/
		const Ciphertext<Element>& operator+=(const Ciphertext<Element> &other) {
			shared_ptr<Ciphertext<Element>> b(new Ciphertext<Element>(other));
			// ciphertext object has no data yet, i.e., it is zero-initialized
			if (m_elements.size() == 0)
			{
				m_elements = other.m_elements;
			}
			else
			{
				shared_ptr<Ciphertext<Element>> a(new Ciphertext<Element>(*this));
				*this = *(this->GetCryptoContext()->EvalAdd(a, b));
			}
			return *this;
		}

		Ciphertext<Element> operator-(const Ciphertext<Element> &other) const {
			shared_ptr<Ciphertext<Element>> a(new Ciphertext<Element>(*this));
			shared_ptr<Ciphertext<Element>> b(new Ciphertext<Element>(other));
			return *this->GetCryptoContext()->EvalSub(a, b);
		}

		const Ciphertext<Element>& operator-=(const Ciphertext<Element> &other) {
			shared_ptr<Ciphertext<Element>> b(new Ciphertext<Element>(other));
			// ciphertext object has no data yet, i.e., it is zero-initialized
			if (m_elements.size() == 0)
			{
				m_elements = other.m_elements;
			}
			else
			{
				shared_ptr<Ciphertext<Element>> a(new Ciphertext<Element>(*this));
				*this = *(this->GetCryptoContext()->EvalSub(a, b));
			}
			return *this;
		}

		/**
		* Unary negation operator.
		*
		* @param &other is the ciphertext to add with.
		* @return the result of the addition.
		*/
		const Ciphertext<Element> operator-() {
			if (m_elements.size() == 0)
				throw std::logic_error("No elements in the ciphertext to be negated");
			else
			{
				shared_ptr<Ciphertext<Element>> a(new Ciphertext<Element>(*this));
				return *(this->GetCryptoContext()->EvalNegate(a));
			}
		}

		Ciphertext<Element> operator*(const Ciphertext<Element> &other) const {
			shared_ptr<Ciphertext<Element>> a(new Ciphertext<Element>(*this));
			shared_ptr<Ciphertext<Element>> b(new Ciphertext<Element>(other));
			return *this->GetCryptoContext()->EvalMult(a, b);
		}

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &other is the ciphertext to add with.
		* @return the result of the addition.
		*/
		const Ciphertext<Element>& operator*=(const Ciphertext<Element> &other) {
			shared_ptr<Ciphertext<Element>> b(new Ciphertext<Element>(other));
			// ciphertext object has no data yet, i.e., it is zero-initialized
			if (m_elements.size() == 0)
			{
				m_elements = other.m_elements;
			}
			else
			{
				shared_ptr<Ciphertext<Element>> a(new Ciphertext<Element>(*this));
				*this = *(this->GetCryptoContext()->EvalMult(a, b));
			}
			return *this;
		}

	private:

		//FUTURE ENHANCEMENT: current value of error norm
		//BigInteger m_norm;

		std::vector<Element> m_elements;		/*!< vector of ring elements for this Ciphertext */
		size_t m_depth; // holds the multiplicative depth of the ciphertext.
		PlaintextEncodings	encodingType;	/*!< how was this Ciphertext encoded? */
	};

	/**
	* Addition operator overload.  Performs EvalAdd.
	*
	* @tparam Element a ring element.
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of addition.
	*/
	template <class Element>
	Ciphertext<Element> operator+(const Ciphertext<Element> &a, const Ciphertext<Element> &b) {
		shared_ptr<Ciphertext<Element>> aPtr(new Ciphertext<Element>(a));
		shared_ptr<Ciphertext<Element>> bPtr(new Ciphertext<Element>(b));
		return *a.GetCryptoContext()->EvalAdd(aPtr,bPtr);
	}

	/**
	* Subtraction operator overload.  Performs EvalSub.
	*
	* @tparam Element a ring element.
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of subtraction.
	*/
	template <class Element>
	Ciphertext<Element> operator-(const Ciphertext<Element> &a, const Ciphertext<Element> &b) {
		shared_ptr<Ciphertext<Element>> aPtr(new Ciphertext<Element>(a));
		shared_ptr<Ciphertext<Element>> bPtr(new Ciphertext<Element>(b));
		return *a.GetCryptoContext()->EvalSub(aPtr, bPtr);
	}
	/**
	* Multiplication operator overload.  Performs EvalMult.
	*
	* @tparam Element a ring element.
	* @param &a the first parameter.
	* @param &b the first parameter.
	*
	* @return The result of multiplication.
	*/
	template <class Element>
	Ciphertext<Element> operator*(const Ciphertext<Element> &a, const Ciphertext<Element> &b) {
		shared_ptr<Ciphertext<Element>> aPtr(new Ciphertext<Element>(a));
		shared_ptr<Ciphertext<Element>> bPtr(new Ciphertext<Element>(b));
		return *a.GetCryptoContext()->EvalMult(aPtr, bPtr);
	}
} // namespace lbcrypto ends
#endif
