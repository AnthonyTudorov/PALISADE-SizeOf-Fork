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

#ifndef LBCRYPTO_UTILS_PLAINTEXT_H
#define LBCRYPTO_UTILS_PLAINTEXT_H

#include <vector>
#include <initializer_list>
#include <iostream>
#include "encodingparams.h"
#include "../utils/inttypes.h"
#include "../math/backend.h"
#include "../lattice/elemparams.h"
#include "../lattice/dcrtpoly.h"
#include "../lattice/ilparams.h"
#include "../lattice/ildcrtparams.h"
#include "../lattice/poly.h"

namespace lbcrypto
{

enum PlaintextEncodings {
	Unknown,
	Scalar,
	ScalarSigned,
	Integer,
	CoefPacked,
	CoefPackedSigned,
	Packed,
	String,
};

/**
 * @class Plaintext
 * @brief This class represents plaintext in the Palisade library.
 *
 * Plaintext is primarily intended to be
 * used as a container and in conjunction with specific encodings which inherit from this class
 * which depend on the application the plaintext is used with.  It provides virtual methods for encoding
 * and decoding of data.
 */
class Plaintext
{
protected:
	bool								isEncoded;
	Poly								encodedVector;
	DCRTPoly							encodedVectorDCRT;
	enum { IsPoly, IsDCRTPoly }			typeFlag;
	shared_ptr<EncodingParams>			encodingParams;

public:
	Plaintext(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, bool isEncoded = false) :
		isEncoded(isEncoded), typeFlag(IsPoly), encodingParams(ep), encodedVector(vp,COEFFICIENT) {}

	Plaintext(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, bool isEncoded = false) :
		isEncoded(isEncoded), typeFlag(IsDCRTPoly), encodingParams(ep), encodedDCRTVector(vp,COEFFICIENT) {}

	virtual ~Plaintext() {}

	/**
	 * GetEncodingTyoe
	 * @return Encoding type used by the class
	 */
	virtual PlaintextEncodings GetEncodingType() const = 0;

	/**
	 * IsEncoded
	 * @return true when encoding is done
	 */
	bool IsEncoded() const { return isEncoded; }

	/**
	 * Encode the plaintext into a polynomial
	 * @return true on success
	 */
	virtual bool Encode() = 0;

	/**
	 * Decode the polynomial into the plaintext
	 * @return
	 */
	virtual bool Decode() = 0;

	/**
	 * GetElement
	 * @return the Polynomial that the element was encoded into
	 */
	template <typename Element>
	Element& GetElement();

	/**
	 * GetEncodedElement encodes, if necessary
	 * @return the Polynomial that the element was encoded into
	 */
	Poly& GetEncodedElement() {
		if( !IsEncoded() ) {
			if( !this->Encode() )
				throw std::logic_error("Encode from within GetEncodedElement failed");
		}
		return encodedVector;
	}

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	virtual size_t GetLength() const = 0;

	/**
	 * resize the plaintext; only works for plaintexts that support a resizable vector (coefpacked)
	 * @param newSize
	 */
	virtual void SetLength(size_t newSize) { throw std::logic_error("resize not supported"); }

	virtual const std::string&		GetStringValue() const { throw std::logic_error("not a string"); }
	virtual const uint64_t&			GetIntegerValue() const { throw std::logic_error("not an integer"); }
	virtual const uint32_t&			GetScalarValue() const { throw std::logic_error("not a scalar"); }
	virtual const int32_t&			GetScalarSignedValue() const { throw std::logic_error("not a signed scalar"); }
	virtual const vector<uint32_t>&	GetCoefPackedValue() const { throw std::logic_error("not a packed coefficient vector"); }
	virtual const vector<int32_t>&	GetCoefPackedSignedValue() const { throw std::logic_error("not a signed packed coefficient vector"); }
	virtual const vector<uint32_t>&	GetPackedValue() const { throw std::logic_error("not a packed coefficient vector"); }

	/**
	 * Method to compare two plaintext to test for equivalence.
	 * This method is called by operator==
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	virtual bool CompareTo(const Plaintext& other) const = 0;

	/**
	 * operator== for plaintexts.  This method makes sure the plaintexts are of the same type.
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are the same.
	 */
	bool operator==(const Plaintext& other) const {
		if( typeid(this) != typeid(&other) )
			return false;

		if( this->typeFlag != other.typeFlag )
			return false;

		if( this->encodingParams != other.encodingParams )
			return false;

		return CompareTo(other);
	}

	bool operator!=(const Plaintext& other) const { return !(*this == other); }

	/**
	 * operator<< for ostream integration - calls PrintValue
	 * @param out
	 * @param item
	 * @return
	 */
	friend std::ostream& operator<<(std::ostream& out, const Plaintext& item);

	/**
	 * PrintValue is called by operator<<
	 * @param out
	 */
	virtual void PrintValue(std::ostream& out) const {
		return;
	}

	/**
	 * Method to convert plaintext modulus to a native data type.
	 *
	 * @param ptm - the plaintext modulus.
	 * @return the plaintext modulus in native type.
	 */
	native_int::BigInteger ConvertToNativeModulus(const BigInteger& ptm) {
		static BigInteger largestNative( ~((uint64_t)0) );

		if( ptm > largestNative )
			throw std::logic_error("plaintext modulus of " + ptm.ToString() + " is too big to convert to a native_int integer");

		return native_int::BigInteger( ptm.ConvertToInt() );
	}
};

inline std::ostream& operator<<(std::ostream& out, const Plaintext& item)
{
	item.PrintValue(out);
	return out;
}

/**
 * GetElement
 * @return the Polynomial that the element was encoded into
 */
template <>
inline Poly& Plaintext::GetElement<Poly>() {
	return encodedVector;
}

/**
 * GetElement
 * @return the DCRTPolynomial that the element was encoded into
 */
template <>
inline DCRTPoly& Plaintext::GetElement<DCRTPoly>() {
	return encodedDCRTVector;
}



}

#endif
