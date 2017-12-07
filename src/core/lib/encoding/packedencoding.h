/**
 * @file packedencoding.h Represents and defines plaintext encodings in Palisade with bit packing capabilities.
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
#ifndef LBCRYPTO_UTILS_PACKEDEXTENCODING_H
#define LBCRYPTO_UTILS_PACKEDEXTENCODING_H

#include "inttypes.h"
#include <vector>
#include <initializer_list>
#include "plaintext.h"
#include "encodingparams.h"
#include <functional>
#include <numeric>

namespace lbcrypto
{

/**
 * @class PackedEncoding
 * @brief Type used for representing IntArray types.
 * Provides conversion functions to encode and decode plaintext data as type vector<uint32_t>.
 * This class uses bit packing techniques to enable efficient computing on vectors of integers.
 * It is NOT supported for DCRTPoly
 */

class PackedEncoding : public PlaintextImpl
{
	vector<uint32_t>		value;

public:
	// these two constructors are used inside of Decrypt
	PackedEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep) :
		PlaintextImpl(vp,ep) {}

	PackedEncoding(shared_ptr<NativePoly::Params> vp, shared_ptr<EncodingParams> ep) :
		PlaintextImpl(vp,ep) {}

	PackedEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep) :
		PlaintextImpl(vp,ep) {}

	PackedEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, vector<uint32_t> coeffs) :
		PlaintextImpl(vp,ep), value(coeffs) {}

	PackedEncoding(shared_ptr<NativePoly::Params> vp, shared_ptr<EncodingParams> ep, vector<uint32_t> coeffs) :
		PlaintextImpl(vp,ep), value(coeffs) {}

	PackedEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, vector<uint32_t> coeffs) :
		PlaintextImpl(vp,ep), value(coeffs) {}

	PackedEncoding(shared_ptr<Poly::Params> vp, shared_ptr<EncodingParams> ep, std::initializer_list<uint32_t> coeffs) :
		PlaintextImpl(vp,ep), value(coeffs) {}

	PackedEncoding(shared_ptr<NativePoly::Params> vp, shared_ptr<EncodingParams> ep, std::initializer_list<uint32_t> coeffs) :
		PlaintextImpl(vp,ep), value(coeffs) {}

	PackedEncoding(shared_ptr<DCRTPoly::Params> vp, shared_ptr<EncodingParams> ep, std::initializer_list<uint32_t> coeffs) :
		PlaintextImpl(vp,ep), value(coeffs) {}

	/**
	 * @brief Constructs a container with a copy of each of the elements in rhs, in the same order.
	 * @param rhs - The input object to copy.
	 */
	PackedEncoding(const std::vector<uint32_t> &rhs)
		: PlaintextImpl(shared_ptr<Poly::Params>(0),NULL), value(rhs) {}

	/**
	 * @brief Constructs a container with a copy of each of the elements in il, in the same order.
	 * @param arr the list to copy.
	 */
	PackedEncoding(std::initializer_list<uint32_t> arr)
		: PlaintextImpl(shared_ptr<Poly::Params>(0),NULL), value(arr) {}

	/**
	 * @brief Default empty constructor with empty uninitialized data elements.
	 */
	PackedEncoding()
		: PlaintextImpl(shared_ptr<Poly::Params>(0),NULL), value() {}

	/**
	 * @brief Method to return the initial root.
	 * @param modulus the initial root.
	 */
	static BigInteger GetInitRoot(const BigInteger &modulus) {
		NativeInteger modulusNI(modulus.ConvertToInt());
		return BigInteger(modulusNI.ConvertToInt());
	}

	static usint GetAutomorphismGenerator(const BigInteger &modulus) {
		NativeInteger modulusNI(modulus.ConvertToInt());
		return m_automorphismGenerator[modulusNI];
	}

	bool Encode();

	bool Decode();

	const vector<uint32_t>&	GetPackedValue() const { return value; }

	/**
	 * GetEncodingType
	 * @return this is a Packed encoding
	 */
	PlaintextEncodings GetEncodingType() const { return Packed; }

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	size_t GetLength() const {
		return value.size();
	}

	/**
	 * @brief Method to set encoding params
	 * @param m the encoding cyclotomic order.
	 * @params params data structure storing encoding parameters
	 */
	static void SetParams(usint m, shared_ptr<EncodingParams> params);

	/**
	* @brief Method to set encoding params (this method should eventually be replaced by void SetParams(usint m, shared_ptr<EncodingParams> params);)
	* @params modulus is the plaintext modulus
	* @param m the encoding cyclotomic order.
	*/
	static void SetParams(const BigInteger &modulus, usint m);

	/**
	 * SetLength of the plaintext to the given size
	 * @param siz
	 */
	void SetLength(size_t siz) {
			value.resize(siz);
	}

	/**
	 * Method to compare two plaintext to test for equivalence.  This method does not test that the plaintext are of the same type.
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const PlaintextImpl& other) const {
		const std::vector<uint32_t>& lv = dynamic_cast<const std::vector<uint32_t>&>(*this);
		const std::vector<uint32_t>& rv = dynamic_cast<const std::vector<uint32_t>&>(other);
		return lv == rv;
	}

	/**
	 * @brief Destructor method.
	 */
	static void Destroy();

	void PrintValue(std::ostream& out) const {
		size_t i;
		for (i = 0; i<value.size()-1; i++)
			out << value[i] << ",";
		out << value[i];
	}

private:
	//initial root of unity for plaintext space
	static std::map<NativeInteger, NativeInteger> m_initRoot;
	//modulus and root of unity to be used for Arbitrary CRT
	static std::map<NativeInteger, NativeInteger> m_bigModulus;
	static std::map<NativeInteger, NativeInteger> m_bigRoot;

	//stores the list of primitive roots used in packing.
	static std::map<NativeInteger, usint> m_automorphismGenerator;
	static std::map<NativeInteger, std::vector<usint>> m_toCRTPerm;
	static std::map<NativeInteger, std::vector<usint>> m_fromCRTPerm;

	static void SetParams_2n(usint m, const NativeInteger &modulus);
	static void SetParams_2n(usint m, shared_ptr<EncodingParams> params);

	/**
	* @brief Packs the slot values into aggregate plaintext space.
	*
	* @param ring is the element containing slot values.
	* @param modulus is the plaintext modulus used for packing.
	*/
	template<typename P>
	void Pack(P *ring, const uint32_t &modulus) const;

	/**
	* @brief Unpacks the data from aggregated plaintext to slot values.
	*
	* @param ring is the input polynomial ring in aggregate plaintext.
	* @param modulus is the plaintext modulus used in packing operation.
	*/
	template<typename P>
	void Unpack(P *ring, const uint32_t &modulus) const;

};

}

#endif
