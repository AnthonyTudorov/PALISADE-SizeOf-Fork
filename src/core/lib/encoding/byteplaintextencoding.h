/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>,
 *	Kevin King <4kevinking@gmail.com>
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
 * This code provides a byte array abstraction.
 *
 */
#ifndef LBCRYPTO_UTILS_BYTEPLAINTEXTENCODING_H
#define LBCRYPTO_UTILS_BYTEPLAINTEXTENCODING_H

#include "inttypes.h"
#include <vector>
#include <initializer_list>

#include "../encoding/plaintext.h"

namespace lbcrypto {

/**
 * @brief Type used for representing string BytePlaintextEncoding types.
 * Provides conversion functions to vector<uint8_t> from standard string types.
 */
class BytePlaintextEncoding : public Plaintext, public std::vector<uint8_t> {
public:
    /**
     *  @brief Standard string constructor.
     */
    BytePlaintextEncoding(const std::string& str)
		: std::vector<uint8_t>(std::vector<uint8_t>(str.begin(), str.end())) {}

    /**
     *  @brief C-string string constructor.
     */
    BytePlaintextEncoding(const char* cstr);

    /**
     *  @brief Explicit constructor for C-strings that do not end at the first null
     *  byte.
     */
    BytePlaintextEncoding(const char* cstr, usint len);

    BytePlaintextEncoding(std::vector<uint8_t>::const_iterator sIter, std::vector<uint8_t>::const_iterator eIter)
    	: std::vector<uint8_t>(vector<uint8_t>(sIter, eIter)) {}

	BytePlaintextEncoding(const std::vector<uint8_t> &rhs) : std::vector<uint8_t>(rhs) {}

    BytePlaintextEncoding(std::initializer_list<uint8_t> arr) : std::vector<uint8_t>(arr) {}

    BytePlaintextEncoding() : std::vector<uint8_t>() {}

    /**
     *  @brief C-string assignment.
     */
    BytePlaintextEncoding& operator=(const char* cstr);

    /**
     *  @brief string assignment.
     */
    BytePlaintextEncoding& operator= (const std::string& s);

	/** Interface for the operation of converting from current plaintext encoding to ILVector2n.
	*
	* @param  modulus - used for encoding.
	* @param  *ilVector encoded plaintext - output argument.
	*/
	void Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t start_from=0, size_t length=0) const;

	/** Interface for the operation of converting from ILVector2n to current plaintext encoding.
	*
	* @param  modulus - used for encoding.
	* @param  *ilVector encoded plaintext - input argument.
	*/
	void Decode(const BigBinaryInteger &modulus, ILVector2n *ilVector);

	void Unpad(const BigBinaryInteger &modulus = BigBinaryInteger::ZERO);

	size_t GetChunksize(const usint ring, const BigBinaryInteger& ptm) const;

	size_t GetLength() const { return this->size(); }

	bool CompareTo(const Plaintext& other) const {
		const std::vector<uint8_t>& lv = dynamic_cast<const std::vector<uint8_t>&>(*this);
		const std::vector<uint8_t>& rv = dynamic_cast<const std::vector<uint8_t>&>(other);
		return lv == rv;
	}

	friend std::ostream& operator<<(std::ostream& out, const BytePlaintextEncoding& item) {
		for( int i=0; i<item.size(); i++ )
			out << item.at(i);
		return out;
	}
};

}

#endif
