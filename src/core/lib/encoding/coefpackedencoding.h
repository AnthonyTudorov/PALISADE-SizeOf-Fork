/**
 * @file coefpackedencoding.h Represents and defines packing integers of plaintext objects into polynomial coefficients in Palisade.
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

#ifndef SRC_CORE_LIB_ENCODING_COEFPACKEDENCODING_H_
#define SRC_CORE_LIB_ENCODING_COEFPACKEDENCODING_H_

#include "plaintext.h"
#include <initializer_list>

namespace lbcrypto {

class CoefPackedEncoding: public Plaintext {
	vector<uint32_t>		value;
	vector<int32_t>		valueSigned;
	bool					isSigned;

public:
	// these two constructors are used inside of Decrypt
	CoefPackedEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, bool isSigned = false) :
		Plaintext(vp,ep,true), isSigned(isSigned) {}

	CoefPackedEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, bool isSigned = false) :
		Plaintext(vp,ep,true), isSigned(isSigned) {}

	CoefPackedEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, vector<int32_t> coeffs) :
		Plaintext(vp,ep), valueSigned(coeffs), isSigned(true) {}

	CoefPackedEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, vector<int32_t> coeffs) :
		Plaintext(vp,ep), valueSigned(coeffs), isSigned(true) {}

	CoefPackedEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, vector<uint32_t> coeffs, bool isSigned=false) :
		Plaintext(vp,ep), isSigned(isSigned) {
		if( isSigned ) valueSigned.insert(valueSigned.begin(), coeffs.begin(),coeffs.end());
		else value = coeffs;
	}

	CoefPackedEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, vector<uint32_t> coeffs, bool isSigned=false) :
		Plaintext(vp,ep), isSigned(isSigned) {
		if( isSigned ) valueSigned.insert(valueSigned.begin(), coeffs.begin(),coeffs.end());
		else value = coeffs;
	}

	virtual ~CoefPackedEncoding() {}

	bool IsSigned() const { return isSigned; }

	/**
	 * GetCoeffsValue
	 * @return the un-encoded scalar
	 */
	const vector<uint32_t>& GetCoefPackedValue() const {
		if( !isSigned )
			return value;
		throw std::logic_error("not a packed coefficient vector");
	}

	/**
	 * GetCoeffsValueSigned
	 * @return
	 */
	const vector<int32_t>& GetCoefPackedSignedValue() const {
		if( isSigned )
			return valueSigned;
		throw std::logic_error("not an unsigned packed coefficient vector");
	}

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
	 * @return this is a CoefPacked encoding
	 */
	PlaintextEncodings GetEncodingType() const { return isSigned ? CoefPackedSigned : CoefPacked; }

	/**
	 * Get length of the plaintext
	 *
	 * @return number of elements in this plaintext
	 */
	size_t GetLength() const { return value.size(); }

	/**
	 * SetLength of the plaintext to the given size
	 * @param siz
	 */
	void SetLength(size_t siz) {
		if( isSigned )
			valueSigned.resize(siz);
		else
			value.resize(siz);
	}

	/**
	 * Method to compare two plaintext to test for equivalence
	 * Testing that the plaintexts are of the same type done in operator==
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const Plaintext& other) const {
		const CoefPackedEncoding& oth = dynamic_cast<const CoefPackedEncoding&>(other);
		return oth.value == this->value && oth.isSigned == this->isSigned;
	}

	/**
	 * PrintValue - used by operator<< for this object
	 * @param out
	 */
	void PrintValue(std::ostream& out) const {
		// for sanity's sake, trailing zeros get elided into "..."
		out << "(";
		size_t i = isSigned ? valueSigned.size() : value.size();
		while( --i > 0 )
			if( isSigned ? valueSigned[i] != 0 : value[i] != 0 )
				break;

		if( isSigned )
			for( size_t j = 0; j <= i; j++ )
				out << ' ' << valueSigned[j];
		else
			for( size_t j = 0; j <= i; j++ )
				out << ' ' << value[j] << 'U';

		out << " ... )";
	}
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_COEFPACKEDENCODING_H_ */
