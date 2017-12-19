/**
 * @file integerencoding.h Represents and defines integer-encoded plaintext objects in Palisade.
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

#include "integerencoding.h"

namespace lbcrypto {

bool
IntegerEncoding::Encode() {
	if( this->isEncoded ) return true;

	auto mod = this->encodingParams->GetPlaintextModulus();
	uint64_t entry = value;

	if( mod < 2 )
		throw std::logic_error("Plaintext modulus must be 2 or more for integer encoding");

	if( this->isSigned ) {
		if( mod % 2 != 0 ) {
			throw std::logic_error("Plaintext modulus must be an even number for signed IntegerEncoding");
		}

		entry = valueSigned;
		if( valueSigned < 0 ) {
			entry = mod + valueSigned;
		}
	}

	if( this->typeFlag == IsNativePoly ) {
		this->encodedNativeVector.SetValuesToZero();

		if( log2((double)value) > (double)this->encodedNativeVector.GetLength() )
			throw std::logic_error("Plaintext value " + std::to_string(value) + " will not fit in encoding of length " + std::to_string(this->encodedVector.GetLength()));

		uint64_t val = entry;
		size_t i = 0;

		while( val > 0 ) {
			this->encodedNativeVector[i++] = val & 0x01;
			val >>= 1;
		}
	}
	else {
		this->encodedVector.SetValuesToZero();

		if( log2((double)value) > (double)this->encodedVector.GetLength() )
			throw std::logic_error("Plaintext value " + std::to_string(value) + " will not fit in encoding of length " + std::to_string(this->encodedVector.GetLength()));

		uint64_t val = entry;
		size_t i = 0;

		while( val > 0 ) {
			this->encodedVector[i++] = val & 0x01;
			val >>= 1;
		}
	}

	if( this->typeFlag == IsDCRTPoly ) {
		this->encodedVectorDCRT = this->encodedVector;
	}

	this->isEncoded = true;
	return true;
}

template<typename P>
static uint64_t decodePoly(const P& poly, const PlaintextModulus& ptm, bool isSigned) {
	uint64_t result = 0;
	uint64_t powerFactor = 1;
	uint64_t half(ptm >> 1);

	for (size_t i = 0; i < poly.GetLength(); i++) {

		auto val = poly[i].ConvertToInt();

		if( val != 0 ) {
			if (val < half)
				result += powerFactor * val;
			else
				result -= powerFactor * (ptm - val);
		}

		// multiply the power factor by 2
		powerFactor <<= 1;
	}

	if( isSigned ) {
		if (result > half)
			result -= ptm;
	}

	return result;
}

bool
IntegerEncoding::Decode() {
	auto modulus = this->encodingParams->GetPlaintextModulus();
	uint64_t val;
	if( this->typeFlag == IsNativePoly )
		val = decodePoly(this->encodedNativeVector, modulus, isSigned);
	else
		val = decodePoly(this->encodedVector, modulus, isSigned);

	if( isSigned ) {
		if( (int64_t)val > (int64_t)(modulus/2) )
			val -= modulus;

		valueSigned = (int64_t)val;
	}
	else value = val;

	return true;
}


} /* namespace lbcrypto */
