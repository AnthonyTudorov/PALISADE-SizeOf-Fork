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
 */
template <typename Element>
class ILElement : public Serializable
{
public:
	// note that there's no constructor here in the base class; it contains no data to construct

	virtual ~ILElement() {}

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
	virtual Element CloneWithNoise(const DiscreteGaussianGenerator &dgg, Format format = EVALUATION) const = 0;

	/**
	 * Test function to prints all values in either coefficient or evaluation format.
	 * FIXME: it might be better to overload operator<<
	 */
	virtual void PrintValues() const = 0;

	/**
	 * Adds one to every entry of the Element, in place
	 */
	virtual void AddILElementOne() = 0;

	/**
	 * Performs the Automorphism Transform on the Element
	 * FIXME: a better comment!
	 * @param i
	 * @return
	 */
	virtual Element AutomorphismTransform(const usint& i) const = 0;

	/**
	 * FIXME: comment
	 * @param baseBits
	 * @return
	 */
	virtual std::vector<Element> BaseDecompose(usint baseBits) const = 0;

	/**
	 * FIXME: comment
	 */
	virtual void Decompose() = 0;

	/**
	 * Divide the element by q and round it
	 * FIXME: comment
	 * @param q
	 * @return result of the operation
	 */
	virtual Element DivideAndRound(const BigBinaryInteger &q) const = 0;

	// GETTERS
	virtual Format GetFormat() const = 0;

	virtual usint GetLength() const = 0;

	virtual const BigBinaryInteger& GetModulus() const = 0;

	virtual const BigBinaryVector& GetValues() const = 0;

	virtual const usint GetCyclotomicOrder() const = 0;

	virtual Element GetDigitAtIndexForBase(usint index, usint base) const = 0;

	virtual bool InverseExists() const = 0;

	virtual bool IsEmpty() const = 0;

	virtual void MakeSparse(const BigBinaryInteger &wFactor) = 0;

	/**
	 * Gets the Value in the Element that is At Index and returns it
	 *
	 * This is only implemented for some derived classes, so the default implementation throws an exception
	 *
	 * @param i
	 * @return will throw a logic_error.
	 */
	virtual const BigBinaryInteger& GetValAtIndex(usint i) const {
		throw std::logic_error("GetValAtIndex not implemented");
	}

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

	/**
	 * SetValAtIndex
	 *
	 * This is only implemented for some derived classes, so the default implementation throws an exception
	 *
	 * @param index
	 * @param val
	 */
	virtual void SetValAtIndex(size_t index, const BigBinaryInteger& val) {
		throw std::logic_error("SetValAtIndex not implemented");
	}

	/**
	 * SetValues allows Element values to be changed; this is used internally by the various operators
	 *
	 * @param values
	 * @param format
	 */
	virtual void SetValues(const BigBinaryVector& values, Format format) = 0;

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
	 * FIXME: comment
	 * @param p
	 * @param q
	 * @return
	 */
	virtual Element MultiplyAndRound(const BigBinaryInteger &p, const BigBinaryInteger &q) const = 0;

	/**
	 * ModReduce reduces the composite modulus by dropping the last modulus from the chain of moduli as well as dropping the last tower.
	 * It's only implemented in the derived class for ILVectorArray2n
	 *
	 *@param plaintextModulus is the plaintextModulus used for the ILVectorArray2n
	 */
	virtual void ModReduce(const BigBinaryInteger &plaintextModulus) {
		throw std::logic_error("ModReduce is not implemented");
	}

	/**
	 * Calculate a vector of elements by raising the base element to successive powers
	 * FIXME: comment
	 * @param baseBits
	 * @return
	 */
	virtual std::vector<Element> PowersOfBase(usint baseBits) const = 0;

	// The core of the arithmetic operations
	virtual Element Minus(const BigBinaryInteger &element) const = 0;
	virtual Element Minus(const Element &element) const = 0;
	virtual Element Plus(const BigBinaryInteger &element) const = 0;
	virtual Element Plus(const Element &element) const = 0;
	virtual Element Times(const BigBinaryInteger &element) const = 0;
	virtual Element Times(const Element &element) const = 0;

	/**
	 * Virtual interface for interpolation based on the Chinese Remainder Transform Interpolation.
	 *
	 * @return the original ring element.
	 */
	virtual Element CRTInterpolate() const = 0;

	virtual Element SignedMod(const BigBinaryInteger &modulus) const = 0;

	virtual void SwitchModulus(const BigBinaryInteger &modulus, const BigBinaryInteger &rootOfUnity) = 0;

	virtual void SwitchFormat() = 0;

	// Serialization
	virtual bool Deserialize(const Serialized& serObj) = 0;
	virtual bool Serialize(Serialized* serObj) const = 0;

	// Assignment operators
	virtual const Element& operator=(const Element& rhs) = 0;
	virtual const Element& operator=(Element&& rhs) = 0;
	virtual const Element& operator=(std::initializer_list<sint> rhs) = 0;

	// overloaded op= operators
	virtual const Element& operator+=(const BigBinaryInteger &element) = 0;

	virtual const Element& operator-=(const BigBinaryInteger &element) = 0;

	virtual const Element& operator*=(const BigBinaryInteger &element) = 0;

	virtual const Element& operator+=(const Element &element) = 0;

	virtual const Element& operator-=(const Element &element) = 0;

	virtual const Element& operator*=(const Element &element) = 0;

	virtual bool operator==(const Element& element) const = 0;

	inline bool operator!=(const Element &element) const {
		return !(*this == element);
	}
};

/**
 * Addition operator overload.  Performs an addition in the ring.
 *
 * @param &a the first parameter.
 * @param &b the first parameter.
 *
 * @return The result of addition in the ring.
 */
template <typename Element>
inline Element operator+(const Element &a, const Element &b) { return a.Plus(b); }

/**
 * Addition operator overload.  Performs an addition in the ring.
 *
 * @param &a the first parameter.
 * @param &b the first parameter.
 *
 * @return The result of addition in the ring.
 */
template <typename Element>
inline Element operator+(const Element &a, const BigBinaryInteger &b) { return a.Plus(b); }

/**
 * Addition operator overload.  Performs an addition in the ring.
 *
 * @param &a the first parameter.
 * @param &b the first parameter.
 *
 * @return The result of addition in the ring.
 */
template <typename Element>
inline Element operator+(const BigBinaryInteger &a, const Element &b) { return b.Plus(a); }

// the following two overloads here in the base class confused the heck out of the compiler
// so they are replicated in the derived classes
//	/**
//	* Subtraction operator overload.  Performs a subtraction in the ring.
//	*
//	* @param &a the first parameter.
//	* @param &b the first parameter.
//	*
//	* @return The result of subtraction in the ring.
//	*/
//	template <typename Element>
//	inline Element operator-(const Element &a, const Element &b) { return a.Minus(b); }
//
//	/**
//	* Subtraction operator overload.  Performs a subtraction in the ring.
//	*
//	* @param &a the first parameter.
//	* @param &b the first parameter.
//	*
//	* @return The result of subtraction in the ring.
//	*/
//	template <typename Element>
//	inline Element operator-(const Element &a, const BigBinaryInteger &b) { return a.Minus(b); }

/**
 * Multiplication operator overload.  Performs a multiplication in the ring.
 *
 * @param &a the first parameter.
 * @param &b the first parameter.
 *
 * @return The result of multiplication in the ring.
 */
template <typename Element>
inline Element operator*(const Element &a, const Element &b) { return a.Times(b); }

/**
 * Multiplication operator overload.  Performs a multiplication in the ring.
 *
 * @param &a the first parameter.
 * @param &b the first parameter.
 *
 * @return The result of multiplication in the ring.
 */
template <typename Element>
inline Element operator*(const Element &a, const BigBinaryInteger &b) { return a.Times(b); }

/**
 * Multiplication operator overload.  Performs a multiplication in the ring.
 *
 * @param &a the first parameter.
 * @param &b the first parameter.
 *
 * @return The result of multiplication in the ring.
 */
template <typename Element>
inline Element operator*(const BigBinaryInteger &a, const Element &b) { return b.Times(a); }

} // namespace lbcrypto ends

#endif
