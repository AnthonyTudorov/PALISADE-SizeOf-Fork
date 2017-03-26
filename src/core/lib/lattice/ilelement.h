/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Hadi Sajjadpour <ss2959@njit.edu>
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
 * LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
 * This code provides basic lattice ideal manipulation functionality.
 */

#ifndef LBCRYPTO_LATTICE_ILELEMENT_H
#define LBCRYPTO_LATTICE_ILELEMENT_H

#include "../math/backend.h"
#include "../utils/inttypes.h"
#include "../math/nbtheory.h"
#include "../math/discretegaussiangenerator.h"

namespace lbcrypto {

/**
 * @brief Interface for ideal lattices
 *
 * Every lattice must implement these pure virtuals in order to properly interoperate with PALISADE PKE
 *
 * Element is the return type for all of these virtual functions
 */
template <typename Element, typename ModType, typename IntType, typename VecType>
class ILElement : public Serializable
{
public:
	// note that there's no constructor here in the base class; it contains no data to construct

	/**
	 * Clone the object by making a copy of it and returning the copy
	 * @return new Element
	 */
	virtual Element Clone() const = 0;

	/**
	 * Clone the object, but have it contain nothing
	 * @return new Element
	 */
	virtual Element CloneEmpty() const = 0;

	/**
	 * Clones the element's parameters, leaves vector initialized to 0
	 * @return new Element
	 */
	virtual Element CloneParametersOnly() const = 0;

	/**
	 * Clones the element with parameters and with noise for the vector
	 * @param dgg
	 * @param format
	 * @return new Element
	 */
	virtual Element CloneWithNoise(const DiscreteGaussianGeneratorImpl<IntType,VecType> &dgg, Format format = EVALUATION) const = 0;

	/**
	 * destructor
	 */
	virtual ~ILElement() {}

	// Assignment operators
	virtual const Element& operator=(const Element& rhs) = 0;
	virtual const Element& operator=(Element&& rhs) = 0;
	virtual const Element& operator=(std::initializer_list<sint> rhs) = 0;

	// GETTERS
	/**
	 * Get format of the element
	 *
	 * @return COEFFICIENT or EVALUATION
	 */
	virtual Format GetFormat() const = 0;

	/**
	 * Get the length of the element.
	 *
	 * @return length
	 */
	virtual usint GetLength() const = 0;

	/**
	 * Get modulus of the element
	 *
	 * @return the modulus.
	 */
	virtual const ModType &GetModulus() const = 0;

	/**
	 * Get the values for the element
	 *
	 * @return the vector.
	 */
	virtual const VecType &GetValues() const = 0;

	/**
	 * Get the cyclotomic order
	 *
	 * @return order
	 */
	virtual const usint GetCyclotomicOrder() const = 0;

	/**
	 * Gets the Value in the Element that is At Index and returns it
	 *
	 * This is only implemented for some derived classes, so the default implementation throws an exception
	 *
	 * @param i
	 * @return will throw a logic_error.
	 */
	virtual const IntType& GetValAtIndex(usint i) const {
		throw std::logic_error("GetValAtIndex not implemented");
	}

	//SETTERS
	/**
	 * Set the Value in the Element that is At Index
	 *
	 * This is only implemented for some derived classes, so the default implementation throws an exception
	 *
	 * @param index
	 * @param val
	 */
	virtual void SetValAtIndex(size_t index, int val) {
		throw std::logic_error("SetValAtIndex not implemented");
	}

	// SETTERS
	/**
	 * SetValAtIndex
	 *
	 * This is only implemented for some derived classes, so the default implementation throws an exception
	 *
	 * @param index
	 * @param val
	 */
	virtual void SetValAtIndex(size_t index, const IntType& val) {
		throw std::logic_error("SetValAtIndex not implemented");
	}

	/**
	 * SetValues allows Element values to be changed; this is used internally by the various operators
	 *
	 * @param values
	 * @param format
	 */
	virtual void SetValues(const VecType& values, Format format) = 0;

	// OPERATORS
	/**
	 * Scalar addition - add an element to the first index only.
	 * This operation is only allowed in COEFFICIENT format.
	 *
	 * @param &element is the element to add entry-wise.
	 * @return is the return of the addition operation.
	 */
	virtual Element Plus(const IntType &element) const = 0;

	/**
	 * Scalar subtraction - subtract an element frp, all entries.
	 *
	 * @param &element is the element to subtract entry-wise.
	 * @return is the return value of the minus operation.
	 */
	virtual Element Minus(const IntType &element) const = 0;

	/**
	 * Scalar multiplication - multiply all entries.
	 *
	 * @param &element is the element to multiply entry-wise.
	 * @return is the return value of the times operation.
	 */
	virtual Element Times(const IntType &element) const = 0;

	/**
	 * Performs an addition operation and returns the result.
	 *
	 * @param &element is the element to add with.
	 * @return is the result of the addition.
	 */
	virtual Element Plus(const Element &element) const = 0;

	/**
	 * Performs a subtraction operation and returns the result.
	 *
	 * @param &element is the element to subtract with.
	 * @return is the result of the subtraction.
	 */
	virtual Element Minus(const Element &element) const = 0;

	/**
	 * Performs a multiplication operation and returns the result.
	 *
	 * @param &element is the element to multiply with.
	 * @return is the result of the multiplication.
	 */
	virtual Element Times(const Element &element) const = 0;

	// overloaded op= operators
	/**
	 * Performs += operation with a BigBinaryInteger and returns the result.
	 *
	 * @param &element is the element to add
	 * @return is the result of the addition.
	 */
	virtual const Element& operator+=(const IntType &element) = 0;

	/**
	 * Performs -= operation with a BigBinaryInteger and returns the result.
	 *
	 * @param &element is the element to subtract
	 * @return is the result of the addition.
	 */
	virtual const Element& operator-=(const IntType &element) = 0;

	/**
	 * Performs *= operation with a BigBinaryInteger and returns the result.
	 *
	 * @param &element is the element to multiply by
	 * @return is the result of the multiplication.
	 */
	virtual const Element& operator*=(const IntType &element) = 0;

	/**
	 * Performs an addition operation and returns the result.
	 *
	 * @param &element is the element to add
	 * @return is the result of the addition.
	 */
	virtual const Element& operator+=(const Element &element) = 0;

	/**
	 * Performs an subtraction operation and returns the result.
	 *
	 * @param &element is the element to subtract
	 * @return is the result of the addition.
	 */
	virtual const Element& operator-=(const Element &element) = 0;

	/**
	 * Performs an multiplication operation and returns the result.
	 *
	 * @param &element is the element to multiply by
	 * @return is the result of the multiplication.
	 */
	virtual const Element& operator*=(const Element &element) = 0;

	virtual bool operator==(const Element& element) const = 0;

	inline bool operator!=(const Element &element) const {
		return !(*this == element);
	}

	/**
	 * Adds one to every entry of the Element, in place
	 */
	virtual void AddILElementOne() = 0;

	/**
	 * Performs an automorphism transform operation and returns the result.
	 *
	 * @param &i is the element to perform the automorphism transform with.
	 * @return is the result of the automorphism transform.
	 */
	virtual Element AutomorphismTransform(const usint& i) const = 0;

	/**
	 * Write the element as \sum\limits{i=0}^{\lfloor {\log q/base} \rfloor} {(base^i u_i)} and
	 * return the vector of {u_0, u_1,...,u_{\lfloor {\log q/base} \rfloor}} \in R_base^{\lceil {\log q/base} \rceil};
	 * used as a subroutine in the relinearization procedure
	 *
	 * @param baseBits is the number of bits in the base, i.e., base = 2^baseBits
	 * @result is the pointer where the base decomposition vector is stored
	 */
	virtual std::vector<Element> BaseDecompose(usint baseBits) const = 0;

	/**
	 * Interpolates based on the Chinese Remainder Transform Interpolation.
	 *
	 * @return the interpolated ring element.
	 */
	virtual Element CRTInterpolate() const = 0;

	/**
	 * Interleaves values in the ILVector2n with odd indices being all zeros.
	 */
	virtual void Decompose() = 0;

	/**
	 * Scalar division followed by rounding operation - operation on all entries.
	 *
	 * @param &q is the element to divide entry-wise.
	 * @return is the return value of the divide, followed by rounding operation.
	 */
	virtual Element DivideAndRound(const IntType &q) const = 0;

	/**
	 * Determines if inverse exists
	 *
	 * @return true id there exists a multiplicative inverse.
	 */
	virtual bool InverseExists() const = 0;

	/**
	 * Returns true if the vector is empty/ m_values==NULL
	 */
	virtual bool IsEmpty() const = 0;

	/**
	 * Make the element Sparse for SHE KeyGen operations.
	 * Sets every index not equal to zero mod the wFactor to zero.
	 *
	 * @param &wFactor ratio between the original element's ring dimension and the new ring dimension.
	 */
	virtual void MakeSparse(const IntType &wFactor) = 0;

	/**
	 * ModByTwo operation on the Element
	 * FIXME: comment
	 * @return result
	 */
	virtual Element ModByTwo() const = 0;

	/**
	 * Calculate and return the Multiplicative Inverse of the element
	 * @return
	 */
	virtual Element MultiplicativeInverse() const = 0;

	/**
	 * Scalar multiplication followed by division and rounding operation - operation on all entries.
	 *
	 * @param &p is the integer muliplicand.
	 * @param &q is the integer divisor.
	 * @return is the return value of the multiply, divide and followed by rounding operation.
	 */
	virtual Element MultiplyAndRound(const IntType &p, const IntType &q) const = 0;

	/**
	 * ModReduce reduces the composite modulus by dropping the last modulus from the chain of moduli as well as dropping the last tower.
	 * It's only implemented in the derived class for ILVectorArray2n
	 *
	 *@param plaintextModulus is the plaintextModulus used for the ILVectorArray2n
	 */
	virtual void ModReduce(const IntType &plaintextModulus) {
		throw std::logic_error("ModReduce is not implemented");
	}

	/**
	 * Calculate a vector of elements by raising the base element to successive powers
	 * FIXME: comment
	 * @param baseBits
	 * @return
	 */
	virtual std::vector<Element> PowersOfBase(usint baseBits) const = 0;

	/**
	 * Test function to prints all values in either coefficient or evaluation format.
	 * FIXME: it might be better to overload operator<<
	 */
	virtual void PrintValues() const = 0;

	/**
	 * SignedMod - perform a modulus operation.
	 * Does proper mapping of [-modulus/2, modulus/2) to [0, modulus)
	 *
	 * @param modulus is the modulus to use.
	 * @return is the return value of the modulus.
	 */
	virtual Element SignedMod(const IntType &modulus) const = 0;

	/**
	 * Switch modulus and adjust the values
	 *
	 * @param &modulus is the modulus to be set.
	 * @param &rootOfUnity is the corresponding root of unity for the modulus
	 * ASSUMPTION: This method assumes that the caller provides the correct rootOfUnity for the modulus.
	 */
	virtual void SwitchModulus(const IntType &modulus, const IntType &rootOfUnity) = 0;

	/**
	 * Convert from Coefficient to CRT or vice versa; calls FFT and inverse FFT.
	 */
	virtual void SwitchFormat() = 0;
};

} // namespace lbcrypto ends

#endif
