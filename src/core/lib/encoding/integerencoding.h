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

#ifndef SRC_CORE_LIB_ENCODING_INTEGERENCODING_H_
#define SRC_CORE_LIB_ENCODING_INTEGERENCODING_H_

#include "plaintext.h"

namespace lbcrypto {

class IntegerEncoding: public PlaintextImpl {
	uint64_t		value;

public:
	// these two constructors are used inside of Decrypt
	IntegerEncoding(shared_ptr<Poly::Params> vp, shared_ptr<Poly::EncodingParams> ep) :
		PlaintextImpl(vp,ep), value(0) {}

	IntegerEncoding(shared_ptr<NativePoly::Params> vp, shared_ptr<NativePoly::EncodingParams> ep) :
		PlaintextImpl(vp,ep), value(0) {}

	IntegerEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<DCRTPoly::EncodingParams> ep) :
		PlaintextImpl(vp,ep), value(0) {}

	IntegerEncoding(shared_ptr<Poly::Params> vp, shared_ptr<Poly::EncodingParams> ep, uint64_t scalar) :
		PlaintextImpl(vp,ep), value(scalar) {}

	IntegerEncoding(shared_ptr<NativePoly::Params> vp, shared_ptr<NativePoly::EncodingParams> ep, uint64_t scalar) :
		PlaintextImpl(vp,ep), value(scalar) {}

	IntegerEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<DCRTPoly::EncodingParams> ep, uint64_t scalar) :
		PlaintextImpl(vp,ep), value(scalar) {}

	virtual ~IntegerEncoding() {}

	/**
	 * GetIntegerValue
	 * @return the un-encoded scalar
	 */
	const uint64_t& GetIntegerValue() const { return value; }

	/**
	 * Encode the plaintext into the Poly
	 * @return true on success
	 */
	bool Encode();

	/**
	 * Decode the Poly into the string
	 * @return true on success
	 */
	bool Decode();

	/**
	 * GetEncodingType
	 * @return this is an Integer encoding
	 */
	PlaintextEncodings GetEncodingType() const { return Integer; }

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
	bool CompareTo(const PlaintextImpl& other) const {
		const IntegerEncoding& oth = dynamic_cast<const IntegerEncoding&>(other);
		return oth.value == this->value;
	}

	/**
	 * PrintValue - used by operator<< for this object
	 * @param out
	 */
	void PrintValue(std::ostream& out) const {
		out << value;
	}
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_INTEGERENCODING_H_ */
