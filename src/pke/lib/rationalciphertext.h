/**
* @file		rationalciphertext.h
*
* @author	TPOC:
Dr. Kurt Rohloff <rohloff@njit.edu>,
Programmers:
Dr. Yuriy Polyakov <polyakov@njit.edu>

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
* This file contains the representation of Ciphertexts for rational plaintext elements
*/

#ifndef LBCRYPTO_CRYPTO_RATIONALCIPHERTEXT_H
#define LBCRYPTO_CRYPTO_RATIONALCIPHERTEXT_H

//Includes Section
#include "palisade.h"
#include "ciphertext.h"

namespace lbcrypto {

	/**
	* @brief RationalCiphertext
	*
	* The RationalCiphertext object is used to contain rational ciphertext data (with numerator and denominator)
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class RationalCiphertext : public Serializable {
	public:

		/**
		* Default constructor
		*/
		RationalCiphertext() {}

		/**
		 * Construct a new ciphertext in the given context
		 *
		 * @param cc
		 */
		RationalCiphertext(CryptoContext<Element> cc) {
			m_numerator = std::make_shared<Ciphertext<Element>>(cc);
			m_denominator = std::make_shared<Ciphertext<Element>>(cc);
		}

		/**
		* Construct a new rational ciphertext from two integer ciphertexts
		*
		* @param cc
		*/
		RationalCiphertext(const Ciphertext<Element> &numerator, const Ciphertext<Element> &denominator) {
			m_numerator = std::make_shared<Ciphertext<Element>>(numerator);
			m_denominator = std::make_shared<Ciphertext<Element>>(denominator);
		}

		/**
		* Copy constructor
		*/
		RationalCiphertext(const RationalCiphertext<Element> &ciphertext) {
			m_numerator = std::make_shared<Ciphertext<Element>>(*ciphertext.m_numerator);
			m_denominator = std::make_shared<Ciphertext<Element>>(*ciphertext.m_denominator);
		}

		/**
		* Move constructor
		*/
		RationalCiphertext(RationalCiphertext<Element> &&ciphertext) {
			m_numerator = ciphertext.m_numerator;
			m_denominator = ciphertext.m_denominator;
		}

		/**
		* Destructor
		*/
		~RationalCiphertext() {}

		/**
		* Assignment Operator.
		*
		* @param &rhs the Ciphertext to assign from
		* @return this Ciphertext
		*/
		RationalCiphertext<Element>& operator=(const RationalCiphertext<Element> &rhs) {
			if (this != &rhs) {
				*this->m_numerator = *rhs.m_numerator;
				*this->m_denominator = *rhs.m_denominator;
			}

			return *this;
		}

		/**
		* Move Assignment Operator.
		*
		* @param &rhs the Ciphertext to move from
		* @return this Ciphertext
		*/
		RationalCiphertext<Element>& operator=(RationalCiphertext<Element> &&rhs) {
			if (this != &rhs) {
				this->m_numerator = rhs.m_numerator;
				this->m_denominator = rhs.m_denominator;
			}

			return *this;
		}

		/**
		* Get a reference to crypto parameters.
		* @return the crypto parameters.
		*/
		const CryptoContext<Element>& GetCryptoContext() const { return m_numerator->GetCryptoContext(); }

		/**
		* Get a reference to crypto parameters.
		* @return the crypto parameters.
		*/
		const shared_ptr<LPCryptoParameters<Element>> GetCryptoParameters() const { return m_numerator->GetCryptoContext().GetCryptoParameters(); }

		/**
		 * GetNumerator - get the numerator ciphertext element
		 * @return the numerator
		 */
		const shared_ptr<Ciphertext<Element>> GetNumerator() const { return m_numerator; }

		/**
		* GetDenominator - get the denominator ciphertext element
		* @return the denominator
		*/
		const shared_ptr<Ciphertext<Element>> GetDenominator() const { return m_denominator; }

		/**
		* Sets the numerator element
		* @param &element ciphertext element.
		*/
		void SetNumerator(const Ciphertext<Element> &element) {
			m_numerator = std::make_shared<Ciphertext<Element>>(element);
		}

		/**
		* Sets the denominator element
		* @param &element ciphertext element.
		*/
		void SetDenominator(const Ciphertext<Element> &element) {
			m_denominator = std::make_shared<Ciphertext<Element>>(element);
		}

		/**
		* YSP Jerry will add the code for this one
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		bool Serialize(Serialized* serObj) const {
			//serObj->SetObject();

			//serObj->AddMember("Object", "Ciphertext", serObj->GetAllocator());

			//if( !this->GetCryptoParameters()->Serialize(serObj) )
			//	return false;

			//SerializeVector("Elements", elementName<Element>(), this->m_elements, serObj);

			return true;
		}

		/**
		* YSP Jerry will add the code for this one
		* Populate the object from the deserialization of the Serialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		bool Deserialize(const Serialized& serObj) {
			// deserialization must be done in a crypto context; this object must be initialized before deserializing the elements
			//if( !this->cryptoContext )
			//	return false;

			//Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
			//if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Ciphertext" )
			//	return false;

			//mIter = serObj.FindMember("Elements");
			//if( mIter == serObj.MemberEnd() )
			//	return false;

			//return DeserializeVector<Element>("Elements", elementName<Element>(), mIter, &this->m_elements);

			return true;
		}

		/**
		* Performs an addition operation and returns the result.
		*
		* @param &other is the ciphertext to add with.
		* @return the result of the addition.
		*/
		inline const RationalCiphertext<Element>& operator+=(const RationalCiphertext<Element> &other) {
			// ciphertext object has no data yet, i.e., it is zero-initialized
			if (m_numerator->GetElements().size() == 0)
			{
				*m_numerator = *other.m_numerator;
				*m_denominator = *other.m_denominator;
			}
			else
			{
				this->m_numerator = this->GetCryptoContext().EvalAdd(m_numerator, other.m_numerator);
				//denominator is assumed to be the same in this initial implementation
			}
			return *this;
		}

		/**
		* Unary negation operator.
		*
		* @param &other is the ciphertext to add with.
		* @return the result of the addition.
		*/
		inline const RationalCiphertext<Element> operator-() {
			if (m_numerator->GetElements().size() == 0)
				throw std::logic_error("No elements in the ciphertext to be negated");
			else
			{
				RationalCiphertext<Element> a = RationalCiphertext<Element>(*this);
				a.m_numerator = this->GetCryptoContext().EvalNegate(this->m_numerator);
				return a;
			}
		}

	private:

		shared_ptr<Ciphertext<Element>> m_numerator;
		shared_ptr<Ciphertext<Element>> m_denominator;

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
	inline RationalCiphertext<Element> operator+(const RationalCiphertext<Element> &a, const RationalCiphertext<Element> &b) { 
		RationalCiphertext<Element> result(a);
		result.SetNumerator(*a.GetCryptoContext().EvalAdd(a.GetNumerator(), b.GetNumerator()));
		return result;
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
	inline RationalCiphertext<Element> operator-(const RationalCiphertext<Element> &a, const RationalCiphertext<Element> &b) {
		RationalCiphertext<Element> result(a);
		result.SetNumerator(*a.GetCryptoContext().EvalSub(a.GetNumerator(), b.GetNumerator()));
		return result;
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
	inline RationalCiphertext<Element> operator*(const RationalCiphertext<Element> &a, const RationalCiphertext<Element> &b) {
		RationalCiphertext<Element> result(a);
		result.SetNumerator(*a.GetCryptoContext().EvalMult(a.GetNumerator(), b.GetNumerator()));
		return result;
	}
} // namespace lbcrypto ends
#endif
