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

#ifndef LBCRYPTO_PTXTENCODING_H
#define LBCRYPTO_PTXTENCODING_H

//Includes Section
#include "../utils/inttypes.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

	/**
	* @brief Class describing the ambient (normalized) plaintext space that cryptosystems will predominantly work with in future. To be implemented in future releases.
	*/
	class AmbientPlaintext {
	};

	/**
	* @brief General encoding abstract class that supports basic operations with AmbientPlainext
	*/
	class PlaintextEncodingInterface
	{
	public:
		/**
		* Interface for the operation of converting from current plaintext encoding to AmbientPlaintext.
		*
		* @param  *ambPtxt encoded plaintext - output argument.
		*/
		//virtual long Encode(AmbientPlaintext *ambPtxt) const = 0;
		/**
		* Interface for the operation of converting from AmbientPlaintext to original plaintext encoding.
		*
		* @param &ambPtxt encoded plaintext.
		*/
		//virtual long Decode(const AmbientPlaintext &ambPtxt) const = 0;

		/**
		* Get method to return the length of plaintext
		*/
		virtual size_t GetLength() const = 0;

	};

	/**
	 * @brief Byte array encoding
	 */
	class ByteArrayPlaintextEncoding : public PlaintextEncodingInterface {
	
	public:
		/**
		* Default constructore
		*/
		ByteArrayPlaintextEncoding():m_data("") {
		}

		/**
		* Constructor that loads a byte array
		*
		* @param &byteArray input byte array
		*/
		ByteArrayPlaintextEncoding(const ByteArray &byteArray):m_data(byteArray) {
		}

		/**
		* Implementation of the method of PlaintextEncodingInterface.
		*
		* @param  *ambPtxt encoded plaintext - output argument.
		*/
		//long Encode(AmbientPlaintext *ambPtxt) const { return 0; };
		/**
		* Implementation of the method of PlaintextEncodingInterface.
		*
		* @param &ambPtxt encoded plaintext.
		*/
		//long Decode(const AmbientPlaintext &ambPtxt) { return 0; };

		/**
		* Get method to return the byte array
		*/
		const ByteArray &GetData() const{
			return m_data;
		}

		/**
		* Get method to return the length of byte array
		*/
		size_t GetLength() const{
			return m_data.length();
		}
	
	private:
		ByteArray m_data;
	};

} // namespace lbcrypto ends
#endif
