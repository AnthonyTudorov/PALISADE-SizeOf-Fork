/**
 * @file packedintplaintextencoding.h Represents and defines plaintext encodings in Palisade with bit packing capabilities.
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
#ifndef LBCRYPTO_UTILS_PACKED_INTPLAINTEXTENCODING_H
#define LBCRYPTO_UTILS_PACKED_INTPLAINTEXTENCODING_H

#include "inttypes.h"
#include <vector>
#include <initializer_list>
#include "plaintext.h"
#include <functional>
#include <numeric>

namespace lbcrypto
{

/**
 * @class PackedIntPlaintextEncoding
 * @brief Type used for representing IntArray types.
 * Provides conversion functions to encode and decode plaintext data as type vector<uint32_t>.
 * This method uses bit packing techniques to enable efficient computing on vectors of integers.
 */
class PackedIntPlaintextEncoding : public Plaintext, public std::vector<uint32_t>
{

public:
	/**
	 * @brief Constructor method.
	 * Constructs a container with as many elements as the range [first,last),
	 * with each element emplace-constructed
	 * from its corresponding element in that range, in the same order.
	 * @param sIter Input iterators to the initial and final positions in a range.
	 * The range used is [first,last), which includes all the elements between first
	 * and last, including the element pointed by first but not the element pointed by last.
	 * The function template argument InputIterator shall be an input iterator type that
	 * points to elements of a type from which value_type objects can be constructed.
	 * @param eIter Input iterators to the initial and final positions in a range.
	 * The range used is [first,last), which includes all the elements between first
	 * and last, including the element pointed by first but not the element pointed by last.
	 * The function template argument InputIterator shall be an input iterator type that
	 * points to elements of a type from which value_type objects can be constructed.
	 */
	PackedIntPlaintextEncoding(std::vector<uint32_t>::const_iterator sIter, std::vector<uint32_t>::const_iterator eIter)
		: std::vector<uint32_t>(std::vector<uint32_t>(sIter, eIter)) {}

	/**
	 * @brief Constructs a container with a copy of each of the elements in rhs, in the same order.
	 * @param rhs - The input object to copy.
	 */
	PackedIntPlaintextEncoding(const std::vector<uint32_t> &rhs) : std::vector<uint32_t>(rhs) {}

	/**
	 * @brief Constructs a container with a copy of each of the elements in il, in the same order.
	 * @param arr the list to copy.
	 */
	PackedIntPlaintextEncoding(std::initializer_list<uint32_t> arr) : std::vector<uint32_t>(arr) {}

	/**
	 * @brief Default empty constructor with empty uninitialized data elements.
	 */
	PackedIntPlaintextEncoding() : std::vector<uint32_t>() {}

	/**
	 * @brief Method to return the initial root.
	 * @param modulus the initial root.
	 */
	static BigBinaryInteger GetInitRoot(const BigBinaryInteger &modulus) {
		native_int::BinaryInteger modulusNI(modulus.ConvertToInt());
		return BigBinaryInteger(modulusNI.ConvertToInt());
	}

	static usint GetAutomorphismGenerator(const BigBinaryInteger &modulus) { 
		native_int::BinaryInteger modulusNI(modulus.ConvertToInt());
		return m_automorphismGenerator[modulusNI];  
	}

	/** The operation of converting from current plaintext encoding to ILVector2n.
	*
	* @param  modulus - used for encoding.
	* @param  *ilVector encoded plaintext - output argument.
	* @param  start_from - location to start from.  Defaults to 0.
	* @param  length - length of data to encode.  Defaults to 0.
	*/
	void Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector, size_t start_from = 0, size_t length = 0) const;

	/**
	 * Interface for the operation of converting from current plaintext encoding to ILVector2n.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - output argument.
	 * @param  start_from - location to start from.  Defaults to 0.
	 * @param  length - length of data to encode.  Defaults to 0.
	*/
	void Encode(const BigBinaryInteger &modulus, ILDCRT2n *ilVector, size_t start_from = 0, size_t length = 0) const {
		throw std::logic_error("Encode: Packed encoding is not currently supported for ILVectorArray2n");
	};

	/**
	 * Interface for the operation of converting from ILVector2n to current plaintext encoding.
	 *
	 * @param  modulus - used for encoding.
	 * @param  *ilVector encoded plaintext - input argument.
	 */
	void Decode(const BigBinaryInteger &modulus, ILVector2n *ilVector);

	/** The operation of converting from ILVectorArray2n to current plaintext encoding.
	*
	* @param  modulus - used for encoding.
	* @param  *ilVector encoded plaintext - input argument.
	*/
	void Decode(const BigBinaryInteger &modulus, ILDCRT2n *ilVector) {
		throw std::logic_error("Decode: Packed encoding is not currently supported for ILVectorArray2n");
	}

	/**
	 * Interface for the operation of stripping away unneeded trailing zeros to pad out a short plaintext until one with entries
	 * for all dimensions.
	 *
	 * @param  &modulus - used for encoding.
	 */
	void Unpad(const BigBinaryInteger &modulus) {} // a null op; no padding in int

	/**
	 * Getter for the ChunkSize data.
	 *
	 * @param  ring - the ring dimension.
	 * @param  ptm - the plaintext modulus.
	 * @return ring - the chunk size.
	 */
	virtual size_t GetChunksize(const usint ring, const BigBinaryInteger& ptm) const;

	/**
	 * Get method to return the length of plaintext
	 *
	 * @return the length of the plaintext in terms of the number of bits.
	 */
	size_t GetLength() const {
		return this->size();
	}

	/**
	 * @brief Method to set the modulus and cyclotomic order parameters
	 * @param modulus the encoding modulus.
	 * @param m the encoding cyclotomic order.
	 */
	static void SetParams(const BigBinaryInteger &modulus, usint m);

	/**
	 * Method to compare two plaintext to test for equivalence.  This method does not test that the plaintext are of the same type.
	 *
	 * @param other - the other plaintext to compare to.
	 * @return whether the two plaintext are equivalent.
	 */
	bool CompareTo(const Plaintext& other) const {
		const std::vector<uint32_t>& lv = dynamic_cast<const std::vector<uint32_t>&>(*this);
		const std::vector<uint32_t>& rv = dynamic_cast<const std::vector<uint32_t>&>(other);
		return lv == rv;
	}

	/**
	 * @brief Destructor method.
	 */
	static void Destroy();

	/**
	 * Output stream operator.
	 *
	 * @param out - the output stream.
	 * @param item - the int plaintext to encode with.
	 * @return an output stream.
	 */
	friend std::ostream& operator<<(std::ostream& out, const PackedIntPlaintextEncoding& item) {
		size_t i;
		for (i = 0; i<item.size()-1; i++)
			out << item.at(i) << ",";
		out << item.at(i);
		return out;
	}

private:
	//initial root of unity for plaintext space
	static std::map<native_int::BinaryInteger, native_int::BinaryInteger> m_initRoot;

	//stores the crt coefficients used for packing of slot values
	static std::map<native_int::BinaryInteger, std::vector<native_int::BinaryVector>> m_coefficientsCRT;

	//stores the list of primitive roots used in packing.
	static std::map<native_int::BinaryInteger, native_int::BinaryVector> m_rootList;

	static std::map<native_int::BinaryInteger, usint> m_automorphismGenerator;

	/**
	* @brief Packs the slot values into aggregate plaintext space.
	*
	* @param ring is the element containing slot values.
	* @param modulus is the plaintext modulus used for packing.
	*/
	void Pack(ILVector2n *ring, const BigBinaryInteger &modulus) const;

	/**
	* @brief Generates the permuted root list.
	*
	* @param orig is the vector of sequencial slot values.
	* @param perm is permuted slot values.
	* @param rootList is the original list of primitive roots.
	*/
	static native_int::BinaryVector FindPermutedSlots(const native_int::BinaryVector &orig, const native_int::BinaryVector & perm, const native_int::BinaryVector & rootList);

	/**
	* @brief Initializes the crt coefficients for polynomial interpolation.
	*
	* @param cycloOrder is the cyclotomic order of the polynomial ring.
	* @param modulus is the plaintext modulus used for packing.
	*/
	static void InitializeCRTCoefficients(usint cycloOrder, const native_int::BinaryInteger & modulus);

	/**
	* @brief Generates a list of primitive roots by raising the m_initRoot to every value in totient list.
	*
	* @param cycloOrder is the cyclotomic order of the polynomial ring.
	* @param modulus is the plaintext modulus used for packing.
	* @return vector containing root list
	*/
	static native_int::BinaryVector GetRootVector(const native_int::BinaryInteger &modulus,usint cycloOrder);

	/**
	* @brief Performs Frobenius map and Unpack operation in an efficient way.
	*
	* @param input is the polynomial ring.
	* @param power is the exponent in the frobenius map operation.
	* @param rootListInit is the vector containing primitive roots.
	* @return vector containing slots values.
	*/
	static native_int::BinaryVector SyntheticPolyPowerMod(const native_int::BinaryVector &input, const native_int::BinaryInteger &power, const native_int::BinaryVector &rootListInit);

	/**
	* @brief Unpacks the data from aggregated plaintext to slot values.
	*
	* @param ring is the input polynomial ring in aggregate plaintext.
	* @param modulus is the plaintext modulus used in packing operation.
	*/
	void Unpack(ILVector2n *ring, const BigBinaryInteger &modulus) const;

};

}

#endif
