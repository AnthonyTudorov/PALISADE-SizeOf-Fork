/**
 * @file plaintext.h Represents and defines plaintext objects in Palisade.
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

#ifndef SRC_CORE_LIB_ENCODING_SCALARENCODING_H_
#define SRC_CORE_LIB_ENCODING_SCALARENCODING_H_

#include "plaintext.h"

namespace lbcrypto {

class ScalarEncoding : public Plaintext {
	uint32_t	value;
	bool		isSigned;

public:
	ScalarEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, int32_t scalar) :
		Plaintext(vp,ep), value((int32_t)scalar), isSigned(true) {}
	ScalarEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, uint32_t usscalar) :
		Plaintext(vp,ep), value(usscalar), isSigned(false) {}
	ScalarEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, int32_t scalar) :
		Plaintext(vp,ep), value((int32_t)scalar), isSigned(true) {}
	ScalarEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, uint32_t usscalar) :
		Plaintext(vp,ep), value(usscalar), isSigned(false) {}
	virtual ~ScalarEncoding() {}

	std::string GetEncodingName() const {
		return isSigned ? "SignedScalar" : "Scalar";
	}

	bool Encode();

	bool Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from=0, size_t length=0) const {
		return false;
	}

	/**
	 * Interface for the operation of converting from Poly to current plaintext encoding.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - input argument.
	 */
	bool Decode(const BigInteger &modulus, Poly *ilVector) { return false; }

	/**
	 * Interface for the operation of stripping away unneeded trailing zeros to pad out a short plaintext until one with entries
	 * for all dimensions.
	 *
	 * @param  &modulus - used for encoding.
	 */
	void Unpad(const BigInteger &modulus) {}

	/**
	 * Getter for the ChunkSize data.
	 *
	 * @param  ring - the ring dimension.
	 * @param  ptm - the plaintext modulus.
	 * @return ring - the chunk size.
	 */
	size_t GetChunksize(const usint ring, const BigInteger& ptm) { return 0; }

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	size_t GetLength() const { return 1; }

	/**
	 * Method to compare two plaintext to test for equivalence.  This method does not test that the plaintext are of the same type.
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const Plaintext& other) const {
		const ScalarEncoding& oth = dynamic_cast<const ScalarEncoding&>(other);
		return oth.value == this->value && oth.isSigned == this->isSigned;
	}

};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_SCALARENCODING_H_ */
