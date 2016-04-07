/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>, Nishanth Pasham <np386@njit.edu>
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
 *
 * This file contains the big binary integer functionality.
 */

#ifndef LBCRYPTO_MATH_CPU8BIT_BININT_H
#define LBCRYPTO_MATH_CPU8BIT_BININT_H

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include "../../utils/inttypes.h"
#include "../../utils/memory.h"
#include <functional>
#include "../interface.h"
#include "mempool.h"

/**
 * @namespace cpu8bit
 * The namespace of cpu8bit
 */
namespace cpu8bit {

const usint NUM_DIGIT_IN_PRINTVAL = 25;	//!< @brief The maximum number of digits in bigbinaryinteger. It is used by the cout(ostream) function for printing the bigbinarynumber.
//const usint BIT_LENGTH = 1023;		//!< @brief The number of bits in the bigbinaryinteger. Any operation that crosses this bit limit will throw an exception.
const usint BIT_LENGTH = 1023;
const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.
const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels used in the Barrett reductions.

/**
 * @brief Class for big binary integers.
 */
class BigBinaryInteger //: public lbcrypto::BigBinaryIntegerInterface
{
public:
	/**
	 * Basic constructor.
	 */
	BigBinaryInteger();

	/**
	 * Basic constructor for specifying the integer.
	 *
	 * @param init is the initial integer.
	 */
	//explicit BigBinaryInteger(uschar init);

	/**
	 * Basic constructor for initializing big binary integer from an unsigned integer.
	 *
	 * @param init is the initial integer.
	 */
	explicit BigBinaryInteger(usint init);

	/**
	 * Basic constructor for specifying the integer.
	 *
	 * @param str is the initial integer represented as a string.
	 */
	explicit BigBinaryInteger(const std::string& str);

	/**
	 * Basic constructor for copying a big binary integer
	 *
	 * @param bigInteger is the big binary integer to be copied.
	 */
	explicit BigBinaryInteger(const BigBinaryInteger& bigInteger);

	/**
	 * Basic constructor for move copying a big binary integer
	 *
	 * @param &&bigInteger is the big binary integer to be copied.
	 */
	BigBinaryInteger(BigBinaryInteger &&bigInteger);//move copy constructor

	/**
	 * ???
	 *
	 * @param &rhs is the big binary matrix to test equality with.
	 * @return the return value.
	 */
	virtual BigBinaryInteger&  operator=(const BigBinaryInteger &rhs);

    inline BigBinaryInteger& operator=(usint val) {
        *this = intToBigBinaryInteger(val);
        return *this;
    }

	/**
	 * ???
	 *
	 * @param &&rhs is the big binary matrix to test equality with.
	 * @return the return value.
	 */
	virtual BigBinaryInteger&  operator=(BigBinaryInteger &&rhs);

	/**
	 * Destructor.
	 */
	~BigBinaryInteger();

	//ACCESSORS

	/**
	 * Prints the value to stdout in decimal format.
	 */
	void PrintValueInDec() const;

	/**
	 * Basic set method for setting the value of a big binary integer
	 *
	 * @param str is the string representation of the big binary integer to be copied.
	 */
	virtual void SetValue(const std::string& str);

	/**
	 * Basic set method for setting the value of a big binary integer
	 *
	 * @param a is the big binary integer representation of the big binary integer to be copied.
	 */
	virtual void SetValue(const BigBinaryInteger& a);

	//METHODS

	//regular aritmethic operations

	/**
	 * Addition operation.
	 *
	 * @param b is the value to add.
	 * @return is the result of the addition operation.
	 */
	virtual BigBinaryInteger Plus(const BigBinaryInteger& b) const;

	/**
	 * Subtraction operation.
	 *
	 * @param b is the value to subtract.
	 * @return is the result of the subtraction operation.
	 */
	BigBinaryInteger Minus(const BigBinaryInteger& b) const;

	/**
	 * Multiplication operation.
	 *
	 * @param b is the value to multiply with.
	 * @return is the result of the multiplication operation.
	 */
	BigBinaryInteger Times(const BigBinaryInteger& b) const;

	/**
	 * Division operation.
	 *
	 * @param b is the value to divide by.
	 * @return is the result of the division operation.
	 */
	BigBinaryInteger DividedBy(const BigBinaryInteger& b) const;

	//compare function

	/**
	 * Compare operation.  Returns -1 if this is less than input, 1 if this is greater, 0 otherwise.
	 *
	 * @param a is the value to compare with.
	 * @return is the result of the comparison operation.
	 */
	sint Compare(const BigBinaryInteger& a) const;

	//modular arithmetic operations

	/**
	 * returns the modulus with respect to the input value.
	 *
	 * @param modulus is the modulus to perform.
	 * @return is the result of the modulus operation.
	 */
	virtual BigBinaryInteger Mod(const BigBinaryInteger& modulus) const;
	//Barrett modular reduction algorithm - used in NTT

	/**
	 * returns the Barret modulus with respect to the input modulus and the Barrett value.
	 *
	 * @param modulus is the modulus to perform.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus operation.
	 */
	virtual BigBinaryInteger ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const;

	/**
	 * returns the Barret modulus with respect to the input modulus and the Barrett value.
	 *
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus operation.
	 */
	virtual BigBinaryInteger ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS+1]) const;
	//virtual BigBinaryInteger BigBinaryInteger::ModBarrettKnezevic(const BigBinaryInteger& modulus, const BigBinaryInteger& mu, uschar flag) const;

	/**
	 * returns the modulus inverse with respect to the input value.
	 *
	 * @param modulus is the modulus to perform.
	 * @return is the result of the modulus inverse operation.
	 */
	BigBinaryInteger ModInverse(const BigBinaryInteger& modulus) const;

	/**
	 * Scalar modulus addition.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus addition operation.
	 */
	virtual BigBinaryInteger ModAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

	/**
	 * Scalar Barrett modulus addition.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus addition operation.
	 */
	virtual BigBinaryInteger ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu[BARRETT_LEVELS]) const;

	/**
	 * Scalar Barrett modulus addition.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus addition operation.
	 */
	virtual BigBinaryInteger ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

	/**
	 * Scalar modulus subtraction.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus subtraction operation.
	 */
	virtual BigBinaryInteger ModSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

	/**
	 * Scalar Barrett modulus subtraction.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus subtraction operation.
	 */
	virtual BigBinaryInteger ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

	/**
	 * Scalar Barrett modulus subtraction.
	 *
	 * @param b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus subtraction operation.
	 */
	virtual BigBinaryInteger ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu[BARRETT_LEVELS]) const;

	/**
	 * Scalar modulus multiplication.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	virtual BigBinaryInteger ModMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

	/**
	 * Scalar Barrett modulus multiplication.
	 *
	 * @param b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus multiplication operation.
	 */
	virtual BigBinaryInteger ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

	/**
	 * Scalar Barrett modulus multiplication.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus multiplication operation.
	 */
	virtual BigBinaryInteger ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu[BARRETT_LEVELS]) const;

	/**
	 * Scalar modulus exponentiation.
	 *
	 * @param &b is the scalar to exponentiate at all locations.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus exponentiation operation.
	 */
	virtual BigBinaryInteger ModExp(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

	/**
	 * Addition accumulator.
	 *
	 * @param &b is the value to add.
	 * @return is the result of the addition operation.
	 */
	virtual const BigBinaryInteger& operator+=(const BigBinaryInteger &b);

	/**
	 * Subtraction accumulator.
	 *
	 * @param &b is the value to subtract.
	 * @return is the result of the subtraction operation.
	 */
	virtual const BigBinaryInteger& operator-=(const BigBinaryInteger &b);

	//bit shifting operators

	/**
	 * Left shift operator and creates a new variable as output.
	 *
	 * @param shift is the amount to shift.
	 * @return the result of the shift.
	 */
	virtual BigBinaryInteger  operator<<(usshort shift) const;

	/**
	 * Right shift operator and creates a new variable as output.
	 *
	 * @param shift is the amount to shift.
	 * @return the result of the shift.
	 */
	virtual BigBinaryInteger  operator>>(usshort shift) const;

	/**
	 * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
	 *
	 * @param shift is the amount to shift.
	 * @return the result of the shift.
	 */
	virtual const BigBinaryInteger& operator<<=(usshort shift);

	/**
	 * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
	 *
	 * @param shift is the amount to shift.
	 * @return the result of the shift.
	 */
	virtual const BigBinaryInteger& operator>>=(usshort shift);

	//input/output operators
	/**
	 * ???
	 *
	 * @param os the output stream.
	 * @param &ptr_obj ???.
	 * @return the return value.
	 */
	friend std::ostream& operator<<(std::ostream& os, const BigBinaryInteger &ptr_obj);
	//friend std::istream& operator>>(std::istream& in, BigBinaryInteger *a);

	/**
	 * Stores the value of this BigBinaryInteger in a string object and returns it.
	 * Added by Arnab Deb Gupta <ad479@njit.edu> on 9/21/15.
	 *
	 * @return the value of this BigBinaryInteger as a string.
	 */
	const std::string ToString() const;

	/**
	 * Tests whether the value is a power of 2.
	 *
	 * @param m_numToCheck is the value to check.
	 * @return true if the input is a power of 2, false otherwise.
	 */
	friend bool CheckPowerofTwos(BigBinaryInteger& m_numToCheck);

	/**
	 * Returns the MSB location of the value.
	 *
	 * @return the index of the most significant bit.
	 */
	usint GetMSB()const;

	/**
	 * Get the number of digits using a specific base - support for arbitrary base may be needed.
	 *
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetLengthForBase(usint base) const {return GetMSB();}

	/**
	 * Get the number of digits using a specific base - support for arbitrary base may be needed.
	 *
	 * @param index is the location to return value from in the specific base.
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetDigitAtIndexForBase(usint index, usint base) const;

	/**
	 * Convert the value to an int.
	 *
	 * @return the int representation of the value.
	 */
	usint ConvertToInt() const;

	/**
	 * Convert the value to a double.
	 *
	 * @return the double representation of the value.
	 */
	double ConvertToDouble() const;

	/**
	 * Convert a value from an int to a BigBinaryInt.
	 *
	 * @param m the value to convert from.
	 * @return the int represented as a big binary int.
	 */
	static BigBinaryInteger intToBigBinaryInteger(usint m);

	/**
	 * Convert a string representation of a binary number to a decimal BigBinaryInt.
	 *
	 * @param bitString the binary num in string.
	 * @return the binary number represented as a decimal big binary int.
	 */
	static BigBinaryInteger BinaryToBigBinaryInt(const std::string& bitString);

	/**
	 * Exponentiation of a bigBinaryInteger x. Returns x^p
	 *
	 * @param p the exponent.
	 * @return the big binary integer x^p.
	 */
	BigBinaryInteger Exp(usint p) const;

	//constant definations

	/**
	 * Constant zero.
	 */
	const static BigBinaryInteger ZERO;

	/**
	 * Constant one.
	 */
	const static BigBinaryInteger ONE;

	/**
	 * Constant two.
	 */
	const static BigBinaryInteger TWO;

	/**
	 * Constant THREE.
	 */
	const static BigBinaryInteger THREE;

	/**
	 * Constant four.
	 */
	const static BigBinaryInteger FOUR;

	/**
	 * Constant five.
	 */
	const static BigBinaryInteger FIVE;

	/**
	 * Test equality of the inputs.
	 *
	 * @param a first value to test.
	 * @param b second value to test.
	 * @return true if the inputs are equal.
	 */
	friend bool operator==(const BigBinaryInteger& a, const BigBinaryInteger& b);

	/**
	 * Test inequality of the inputs.
	 *
	 * @param a first value to test.
	 * @param b second value to test.
	 * @return true if the inputs are inequal.
	 */
	friend bool operator!=(const BigBinaryInteger& a, const BigBinaryInteger& b);

	/**
	 * Test if first input is great than the second input.
	 *
	 * @param a first value to test.
	 * @param b second value to test.
	 * @return true if the first inputs is greater.
	 */
	friend bool operator> (const BigBinaryInteger& a, const BigBinaryInteger& b);

	/**
	 * Test if first input is great than or equal to the second input.
	 *
	 * @param a first value to test.
	 * @param b second value to test.
	 * @return true if the first inputs is greater than or equal to the second input.
	 */
	friend bool operator>=(const BigBinaryInteger& a, const BigBinaryInteger& b);

	/**
	 * Test if first input is less than the second input.
	 *
	 * @param a first value to test.
	 * @param b second value to test.
	 * @return true if the first inputs is lesser.
	 */
	friend bool operator< (const BigBinaryInteger& a, const BigBinaryInteger& b);

	/**
	 * Test if first input is less than or equal to the second input.
	 *
	 * @param a first value to test.
	 * @param b second value to test.
	 * @return true if the first inputs is less than or equal to the second input.
	 */
	friend bool operator<=(const BigBinaryInteger& a, const BigBinaryInteger& b);

    /**
     *  Set this int to 1.
     */
    inline void SetIdentity() { *this = intToBigBinaryInteger(1); };

	static std::function<unique_ptr<BigBinaryInteger>()> Allocator;
protected:

	/**
	 * Converts a string into base 256 numbers by the algorithm that you provided me in the beginning of this project.
	 *
	 * @param v The input string
	 */
	void AssignVal(const std::string& v);

	/**
	 * Sets the MSB to the correct value.  Intended as a kind of pre-computation.
	 */
	void SetMSB();

	/**
	 * Gets the bit at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return is the resulting bit.
	 */
	uschar GetBitAtIndex(usint index) const;

	//bit shifting manipulators

	/**
	 * Shifts all the bits left in a big binary integer.  Equivalent to multiplying by 2.
	 *
	 * @param shift is the amount to shift by.
	 * @return is the resulting big binary integer.
	 */
	BigBinaryInteger ShiftLeft(uschar shift) const;

	/**
	 * Shifts all the bits right in a big binary integer.  Equivalent to dividing by 2.
	 *
	 * @param shift is the amount to shift by.
	 * @return is the resulting big binary integer.
	 */
	BigBinaryInteger ShiftRight(uschar shift) const;

private:
	BigBinaryInteger MulIntegerByChar(uschar b) const;
	uschar *m_value;
	usshort m_MSB;
	static usshort m_nchar ;
	static uschar ceilIntBy8(uschar Number);
	//static MemoryPool_uschar memReserve;
	static MemoryPoolChar m_memReserve;
};


//overloaded binary operators based on integer arithmetic and comparison functions
	/**
	 * Addition operation.
	 *
	 * @param a is the value to add.
	 * @param b is the value to add.
	 * @return is the result of the addition operation.
	 */
inline BigBinaryInteger operator+(const BigBinaryInteger &a, const BigBinaryInteger &b) {return a.Plus(b);}

	/**
	 * Subtraction operation.
	 *
	 * @param a is the value to subtract from.
	 * @param b is the value to subtract.
	 * @return is the result of the subtraction operation.
	 */
inline BigBinaryInteger operator-(const BigBinaryInteger &a, const BigBinaryInteger &b) {return a.Minus(b);}

	/**
	 * Multiplication operation.
	 *
	 * @param a is the value to multiply with.
	 * @param b is the value to multiply with.
	 * @return is the result of the multiplication operation.
	 */
inline BigBinaryInteger operator*(const BigBinaryInteger &a, const BigBinaryInteger &b) {return a.Times(b);}

	/**
	 * Division operation.
	 *
	 * @param a is the value to divide.
	 * @param b is the value to divide by.
	 * @return is the result of the division operation.
	 */
inline BigBinaryInteger operator/(const BigBinaryInteger &a, const BigBinaryInteger &b) {return a.DividedBy(b);}

//inline bool operator==(const BigBinaryInteger& a, const BigBinaryInteger& b);
//inline bool operator!=(const BigBinaryInteger& a, const BigBinaryInteger& b);
//inline bool operator> (const BigBinaryInteger& a, const BigBinaryInteger& b);
//inline bool operator>=(const BigBinaryInteger& a, const BigBinaryInteger& b);
//inline bool operator< (const BigBinaryInteger& a, const BigBinaryInteger& b);
//inline bool operator<=(const BigBinaryInteger& a, const BigBinaryInteger& b);

} // namespace lbcrypto ends

#endif
