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
 * This code provides the core proxy re-encryption functionality.
 */

#ifndef LBCRYPTO_ENCODING_BYTEENGODING_H
#define LBCRYPTO_ENCODING_BYTEENGODING_H

//Includes Section
#include "ptxtencoding.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	/**
	 * @brief Byte array encoding
	 */
	class ByteArrayPlaintextEncoding : public PlaintextEncodingInterface {

	public:
		/**
		* Default constructore
		*/
		ByteArrayPlaintextEncoding() : m_data() {}

		/**
		* Constructor that loads an entire byte array
		*
		* @param &byteArray input byte array
		*/
		ByteArrayPlaintextEncoding(const ByteArray &byteArray): m_data(byteArray) {}

		/**
		 * Constructor that loads a portion of a byte array
		 *
		 * @param byteArray
		 * @param start
		 * @param end
		 */
		ByteArrayPlaintextEncoding(const ByteArray &byteArray, const size_t start, const size_t end)
			: m_data( byteArray.begin() + start, min(byteArray.begin() + start + end,byteArray.end()) ) {}

		/**
		* Copy Constructor
		*
		* @param &encoding input plaintext to be copied
		*/
		ByteArrayPlaintextEncoding(const ByteArrayPlaintextEncoding &encoding):
            m_data(encoding.m_data) {
		}

		/**
		* Assignment Operator.
		*
		* @param &&rhs the copied plaintext.
		* @return the resulting plaintext.
		*/
		ByteArrayPlaintextEncoding& operator=(const ByteArrayPlaintextEncoding &rhs)
		{
			if (this != &rhs) {
				this->m_data = rhs.m_data;
			}

			return *this;
		}

		bool operator==(const ByteArrayPlaintextEncoding& that) const;
		bool operator!=(const ByteArrayPlaintextEncoding& that) const { return !( (*this) == that ); }

		/** Method for the operation of converting from current plaintext encoding to ILVector2n.
		*
		* @param  modulus - used for encoding.
		* @param  *ilVector encoded plaintext - output argument.
		*/
		void Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector) const;

		/** Method for the operation of converting from ILVector2n to current plaintext encoding.
		*
		* @param  modulus - used for encoding.
		* @param  ilVector encoded plaintext - input argument.
		*/
		void Decode(const BigBinaryInteger &modulus,  ILVector2n &ilVector);

		
		/** Method for the operation of converting from current plaintext encoding to ILVector2n.
		*
		* @param  modulus - used for encoding.
		* @param  *ilVectorArray2n encoded plaintext - output argument.
		*/
		void Encode(const BigBinaryInteger &modulus, ILVectorArray2n *ilVectorArray2n) const;

		/** Method for the operation of converting from ILVector2n to current plaintext encoding.
		*
		* @param  modulus - used for encoding.
		* @param  ilVectorArray2n encoded plaintext - input argument.
		*/
		void Decode(const BigBinaryInteger &modulus,  ILVectorArray2n &ilVectorArray2n);

		/**
		 * Get method to return the byte array
		 * @return the byte array of data.
		 */
		const ByteArray &GetData() const{
			return m_data;
		}

		/**
		* Get method to return the length of byte array
		*/
		size_t GetLength() const{
			return m_data.size();
		}

		/**
		 * Get method to return a vector of 32-bit integers
		 *
		 * @return the data as vector of integers.
		 */
		std::vector<uint32_t> ToInt32() const;

		/**
		 * @brief Abstract Interface Class to capture Padding operation
		 * @tparam Padding the passing used.
		 */
		template <typename Padding>
		void Pad(const usint blockSize) {
		    static_assert(std::is_base_of<PaddingScheme, Padding>::value,
			"Padding must derive from PaddingScheme");
		    Padding::Pad(blockSize, &m_data);
		}

		/**
		 * @brief Abstract Interface Class to capture Unpadding operation
		 * @tparam Padding the passing used.
		 */
		template <typename Padding>
		void Unpad() {
		    static_assert(std::is_base_of<PaddingScheme, Padding>::value,
			"Padding must derive from PaddingScheme");
		    Padding::Unpad(&m_data);
		}

	private:
		ByteArray m_data;
	};

	std::ostream &operator<<(std::ostream &out, const ByteArrayPlaintextEncoding &ptxt);


} // namespace lbcrypto ends
#endif
