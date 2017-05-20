/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Jerry Ryan <gwryan@njit.edu
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
 * This code provides the abstraction for plaintext in palisade
 *
 */
#ifndef LBCRYPTO_UTILS_PLAINTEXT_H
#define LBCRYPTO_UTILS_PLAINTEXT_H

#include <vector>
#include <initializer_list>
#include <iostream>
#include "../utils/inttypes.h"
#include "../math/backend.h"
#include "../lattice/elemparams.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/ilvector2n.h"
#include "../lattice/ilvectorarray2n.h"

namespace lbcrypto {

class Plaintext {
public:
	virtual ~Plaintext() {}

	/** Interface for the operation of converting from current plaintext encoding to ILVector2n.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - output argument.
	 */
    virtual void Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t start_from=0, size_t length=0) const = 0;

	/** Interface for the operation of converting from ILVector2n to current plaintext encoding.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - input argument.
	 */
	virtual void Decode(const BigBinaryInteger &modulus, ILVector2n *ilVector) = 0;

	virtual void Unpad(const BigBinaryInteger &modulus) = 0;

	virtual size_t GetChunksize(const usint ring, const BigBinaryInteger& ptm) const = 0;

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	virtual size_t GetLength() const = 0;

	virtual bool CompareTo(const Plaintext& other) const = 0;

	bool operator==(const Plaintext& other) const {
		if( typeid(this) != typeid(&other) )
			return false;

		return CompareTo(other);
	}

	native64::BigBinaryInteger ConvertToNativeModulus(const BigBinaryInteger& ptm) {
		static BigBinaryInteger largestNative( ~((uint64_t)0) );

		if( ptm > largestNative )
			throw std::logic_error("plaintext modulus of " + ptm.ToString() + " is too big to convert to a native64 integer");

		return native64::BigBinaryInteger( ptm.ConvertToInt() );
	}
};

}

#endif
