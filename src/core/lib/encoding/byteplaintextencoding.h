/**
 * @file byteplaintextencoding.h Represents and defines plaintext objects in Palisade
 * that encodes bytes of data, notionallt chars.
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
#ifndef LBCRYPTO_UTILS_BYTEPLAINTEXTENCODING_H
#define LBCRYPTO_UTILS_BYTEPLAINTEXTENCODING_H

#include "inttypes.h"
#include <vector>
#include <initializer_list>

#include "../encoding/plaintext.h"
#include "../encoding/stringencoding.h"

namespace lbcrypto
{

/**
 * @class BytePlaintextEncoding
 * @brief Type used for representing string BytePlaintextEncoding types.
 * Provides conversion functions to vector<uint8_t> from standard string types.
 *
 * NOTE this is an older type and its use is deprecated.
 * It is now a wrapper around StringEncoding
 */

class BytePlaintextEncoding : public Plaintext
{
	shared_ptr<Plaintext>	ptxt;
	std::string				str;

public:

	/**
	 * @brief Standard string constructor to encode a string of data as a list of chars.
	 * @param str the input string
	 * @return the resulting plaintext that encodes the bytes.
	 */
	BytePlaintextEncoding(const std::string& str)
		: Plaintext(shared_ptr<Poly::Params>(0),NULL), str(str) {}

//	/**
//	 * @brief C-string string constructor.
//	 * @param cstr char array to be encoded.
//	 * @return A plaintext encoding of the input char string.
//	 */
//	BytePlaintextEncoding(const char* cstr);
//
//	/**
//	 * @brief C-string string constructor.
//	 * @param cstr char array to be encoded.
//	 * @param len the length of the string to encode.
//	 * @return the char string encoded as a plaintext.
//	 */
//	BytePlaintextEncoding(const char* cstr, usint len);

//	/**
//	 * @brief Constructor method.
//	 * Constructs a container with as many elements as the range [first,last),
//	 * with each element emplace-constructed
//	 * from its corresponding element in that range, in the same order.
//	 * @param sIter Input iterators to the initial and final positions in a range.
//	 * The range used is [first,last), which includes all the elements between first
//	 * and last, including the element pointed by first but not the element pointed by last.
//	 * The function template argument InputIterator shall be an input iterator type that
//	 * points to elements of a type from which value_type objects can be constructed.
//	 * @param eIter Input iterators to the initial and final positions in a range.
//	 * The range used is [first,last), which includes all the elements between first
//	 * and last, including the element pointed by first but not the element pointed by last.
//	 * The function template argument InputIterator shall be an input iterator type that
//	 * points to elements of a type from which value_type objects can be constructed.
//	 */
//	BytePlaintextEncoding(std::vector<uint8_t>::const_iterator sIter, std::vector<uint8_t>::const_iterator eIter)
//		: Plaintext(shared_ptr<Poly::Params>(0),NULL), std::vector<uint8_t>(vector<uint8_t>(sIter, eIter)) {}

//	/**
//	 * @brief Constructs a container with a copy of each of the elements in rhs, in the same order.
//	 * @param rhs - The input object to copy.
//	 */
//	BytePlaintextEncoding(const std::vector<uint8_t> &rhs)
//		: Plaintext(shared_ptr<Poly::Params>(0),NULL), std::vector<uint8_t>(rhs) {}

//	/**
//	 * @brief Constructs a container with a copy of each of the elements in il, in the same order.
//	 * @param arr the list to copy.
//	 */
//	BytePlaintextEncoding(std::initializer_list<uint8_t> arr)
//		: Plaintext(shared_ptr<Poly::Params>(0),NULL), std::vector<uint8_t>(arr) {}

	/**
	 * @brief Default empty constructor with empty uninitialized data elements.
	 */
	BytePlaintextEncoding()
		: Plaintext(shared_ptr<Poly::Params>(0),NULL) {}

//	/**
//	 * @brief assignment copy operator.
//	 * @param cstr the input to copy.
//	 */
//	BytePlaintextEncoding& operator=(const char* cstr);
//
//	/**
//	 * @brief String assignment operation.
//	 * @param s the input string to copy into the byte encoded plaintext.
//	 */
//	BytePlaintextEncoding& operator= (const std::string& s);

	size_t size() const { return str.size(); }

	void push_back(char ch) { str.push_back(ch); }

	std::string GetString() const { return this->str; }

	char operator[](size_t idx) const { return this->str[idx]; }

	bool Encode() { return ptxt->Encode(); }

	bool Decode() { return ptxt->Decode(); }

	/**
	 * Interface for the operation of converting from current plaintext encoding to Poly.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - output argument.
	 * @param  start_from - location to start from.  Defaults to 0.
	 * @param  length - length of data to encode.  Defaults to 0.
	 */
	bool Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from=0, size_t length=0) {
		shared_ptr<EncodingParams> ep( new EncodingParams(modulus) );
		this->ptxt.reset( new StringEncoding(ilVector->GetParams(), ep, str) );
		this->Encode();
		ilVector = &ptxt->GetEncodedElement();
		return true;
	}

	/**
	 * Interface for the operation of converting from Poly to current plaintext encoding.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - input argument.
	 */
	bool Decode(const BigInteger &modulus, Poly *ilVector) {
		return false;
	}

	/**
	 * Interface for the operation of stripping away unneeded trailing zeros to pad out a short plaintext until one with entries
	 * for all dimensions.
	 *
	 * @param  &modulus - used for encoding.
	 */
	void Unpad(const BigInteger &modulus = 0) {}

	/**
	 * Getter for the ChunkSize data.
	 *
	 * @param  ring - the ring dimension.
	 * @param  ptm - the plaintext modulus.
	 * @return ring - the chunk size.
	 */
	size_t GetChunksize(const usint ring, const BigInteger& ptm) const;

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	size_t GetLength() const {
		return str.size();
	}

	/**
	 * Method to compare two plaintext to test for equivalence.  This method does not test that the plaintext are of the same type.
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const Plaintext& other) const {
		return this->ptxt->CompareTo(other);
//		const std::vector<uint8_t>& lv = dynamic_cast<const std::vector<uint8_t>&>(*this);
//		const std::vector<uint8_t>& rv = dynamic_cast<const std::vector<uint8_t>&>(other);
//		return lv == rv;
	}

//	/**
//	 * Output stream operator.
//	 *
//	 * @param out - the output stream.
//	 * @param item - the byte plaintext to encode with.
//	 * @return an output stream.
//	 */
//	friend std::ostream& operator<<(std::ostream& out, const BytePlaintextEncoding& item) {
//		for( size_t i=0; i<item.size(); i++ )
//			out << item.at(i);
//		return out;
//	}
};

}

#endif
