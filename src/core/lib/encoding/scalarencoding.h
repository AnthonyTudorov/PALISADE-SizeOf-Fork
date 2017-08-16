/**
 * @file scalarencoding.h Represents and defines scalar-encoded plaintext objects in Palisade.
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
	uint32_t		value;
	int32_t		valueSigned;
	bool			isSigned;

public:
	// these two constructors are used inside of Decrypt
	ScalarEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, bool isSigned = false) :
		Plaintext(vp,ep,true), value(0), valueSigned(0), isSigned(isSigned) {}

	ScalarEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, bool isSigned = false) :
		Plaintext(vp,ep,true), value(0), valueSigned(0), isSigned(isSigned) {}

	ScalarEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, int32_t scalar) :
		Plaintext(vp,ep), value(0), valueSigned(scalar), isSigned(true) {}

	ScalarEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, uint32_t scalar) :
		Plaintext(vp,ep), value(scalar), valueSigned(0), isSigned(false) {}

	ScalarEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, int32_t scalar) :
		Plaintext(vp,ep), value(0), valueSigned(scalar), isSigned(true) {}

	ScalarEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, uint32_t scalar) :
		Plaintext(vp,ep), value(scalar), valueSigned(0), isSigned(false) {}

	virtual ~ScalarEncoding() {}

	bool IsSigned() const { return isSigned; }

	/**
	 * GetScalarValue
	 * @return the un-encoded scalar
	 */
	uint32_t GetScalarValue() const { return value; }

	/**
	 * GetScalarValueSigned
	 * @return the un-encoded scalar
	 */
	uint32_t GetScalarValueSigned() const { return valueSigned; }

	/**
	 * Encode the plaintext into the Poly
	 * @return true on success
	 */
	bool Encode();

	/**
	 * Legacy Encode
	 * @param modulus
	 * @param ilVector
	 * @param start_from
	 * @param length
	 * @return
	 */
	bool Encode(const BigInteger &modulus, Poly *ilVector, size_t start_from=0, size_t length=0) {
		return false;
	}

	/**
	 * Decode the Poly into the string
	 * @return true on success
	 */
	bool Decode();

	/**
	 * Interface for the operation of converting from Poly to current plaintext encoding.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - input argument.
	 */
	bool Decode(const BigInteger &modulus, Poly *ilVector) { return false; }

	/**
	 * GetEncodingType
	 * @return proper type
	 */
	PlaintextEncodings GetEncodingType() const { return isSigned ? ScalarSigned : Scalar; }

	/**
	 * Legacy padding op, does not apply
	 */
	void Unpad(const BigInteger &modulus) {}

	/**
	 * Legacy chunking op, does not apply
	 */
	size_t GetChunksize(const usint ring, const BigInteger& ptm) { return 0; }

	/**
	 * Get length of the plaintext
	 *
	 * @return number of elements in this plaintext
	 */
	size_t GetLength() const { return 1; }

	/**
	 * Method to compare two plaintext to test for equivalence
	 * Testing that the plaintexts are of the same type done in operator==
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const Plaintext& other) const {
		const ScalarEncoding& oth = dynamic_cast<const ScalarEncoding&>(other);
		return oth.value == this->value && oth.isSigned == this->isSigned;
	}

	/**
	 * PrintValue - used by operator<< for this object
	 * @param out
	 */
	void PrintValue(std::ostream& out) const {
		if( isSigned )
			out << valueSigned;
		else
			out << value << "U";
	}
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_SCALARENCODING_H_ */
