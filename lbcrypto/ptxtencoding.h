/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 *
 * All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.
 *
 * This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
 *
 * @section DESCRIPTION
 *
 * This code provides the core proxy re-encryption functionality.
 */

#ifndef LBCRYPTO_PTXTENCODING_H
#define LBCRYPTO_PTXTENCODING_H

//Includes Section
#include "inttypes.h"

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
