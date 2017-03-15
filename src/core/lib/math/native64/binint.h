/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
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
 * This file contains the main class for big integers: NativeInteger. Big integers are represented
 * as arrays of native usigned integers. The native integer type is supplied as a template parameter.
 * Currently implementations based on uint8_t, uint16_t, and uint32_t are supported. The second template parameter
 * is the maximum bitwidth for the big integer.
 */

#ifndef LBCRYPTO_MATH_NATIVE_BININT_H
#define LBCRYPTO_MATH_NATIVE_BININT_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <limits>
#include <fstream>
#include <stdexcept>
#include <functional>
#include <cstdlib>
#include <memory>
#include "../../utils/inttypes.h"
#include "../../utils/memory.h"

/**
 *@namespace native64
 */
namespace native64 {

/**The following structs are needed for initialization of NativeInteger at the preprocessing stage.
 *The structs compute certain values using template metaprogramming approach and mostly follow recursion to calculate value(s).
 */

/**
 * @brief  Struct to find log value of N.
 *Needed in the preprocessing step of NativeInteger to determine bitwidth.
 *
 * @tparam N bitwidth.
 */
template <usint N>
struct Log2 {
	const static usint value = 1 + Log2<N/2>::value;
};

/**
 * @brief Struct to find log value of N.
 *Base case for recursion.
 *Needed in the preprocessing step of NativeInteger to determine bitwidth.
 */
template<>
struct Log2<2> {
	const static usint value = 1;
};

/**
 * @brief Struct to find log value of U where U is a primitive datatype.
 *Needed in the preprocessing step of NativeInteger to determine bitwidth.
 *
 * @tparam U primitive data type.
 */
template <typename U>
struct LogDtype {
	const static usint value = Log2<8*sizeof(U)>::value;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}
 *
 * @tparam Dtype primitive datatype.
 */
template<typename Dtype>
struct DataTypeChecker {
	const static bool value = false ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}.
 * sets value true if datatype is unsigned integer 8 bit.
 */
template<>
struct DataTypeChecker<uint8_t>{
	const static bool value = true ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}.
 * sets value true if datatype is unsigned integer 16 bit.
 */
template<>
struct DataTypeChecker<uint16_t>{
	const static bool value = true ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}.
 * sets value true if datatype is unsigned integer 32 bit.
 */
template<>
struct DataTypeChecker<uint32_t>{
	const static bool value = true ;
};

/**
 * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t}.
 * sets value true if datatype is unsigned integer 64 bit.
 */
template<>
struct DataTypeChecker<uint64_t>{
	const static bool value = true ;
};

/**
 * @brief Struct for calculating bit width from data type.
 * Sets value to the bitwidth of uint_type
 *
 * @tparam uint_type native integer data type.
 */
template <typename uint_type>
struct UIntBitWidth {
	const static int value = 8*sizeof(uint_type);
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type void for default case
 *
 * @tparam utype primitive integer data type.
 */
template<typename utype>
struct DoubleDataType{
	typedef void T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * Sets T as of type unsigned integer 16 bit if integral datatype is 8bit
 */
template<>
struct DoubleDataType<uint8_t>{
	typedef uint16_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 32 bit if integral datatype is 16bit
 */
template<>
struct DoubleDataType<uint16_t>{
	typedef uint32_t T;
};

/**
 * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
 * sets T as of type unsigned integer 64 bit if integral datatype is 32bit
 */
template<>
struct DoubleDataType<uint32_t>{
	typedef uint64_t T;
};

#if !defined(_MSC_VER)
/**
* @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
* sets T as of type unsigned integer 128 bit if integral datatype is 64bit
*/
template<>
struct DoubleDataType<uint64_t>{
	typedef __uint128_t T;
};
#endif


const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.
const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels (precomputed values) used in the Barrett reductions.


/**
 * @brief Main class for big integers represented as an array of native (primitive) unsigned integers
 * @tparam uint_type native unsigned integer type
 * @tparam BITLENGTH maximum bitdwidth supported for big integers
 */
template<typename uint_type>
class NativeInteger
{

public:
	// FIXME overflows in string constructor and in the various ops

	/**
	 * Default constructor.
	 */
	NativeInteger() : m_value(0) {}

	/**
	 * Basic constructor for specifying the integer.
	 *
	 * @param str is the initial integer represented as a string.
	 */
	NativeInteger(const std::string& str) {
		AssignVal(str);
	}

	/**
	 * Basic constructor for initializing big binary integer from an unsigned integer.
	 *
	 * @param init is the initial integer.
	 */
	NativeInteger(const uint_type& init) : m_value(init) {}

	/**
	 * Basic constructor for copying a big binary integer
	 *
	 * @param bigInteger is the big binary integer to be copied.
	 */
	NativeInteger(const NativeInteger& bigInteger) : m_value(bigInteger.m_value) {}

	/**
	 * Assignment operator
	 *
	 * @param &rhs is the big binary integer to be assigned from.
	 * @return assigned BigBinaryIntegr ref.
	 */
	const NativeInteger&  operator=(const NativeInteger &rhs) {
		this->m_value = rhs.m_value;
		return *this;
	}

//	/**
//	 * Assignment operator
//	 *
//	 * @param &rhs is the big binary integer to be assigned from.
//	 * @return assigned BigBinaryIntegr ref.
//	 */
//	const NativeInteger&  operator=(const NativeInteger &&rhs) {
//		this->m_value = rhs.m_value;
//		return *this;
//	}

	/**
	 * Assignment operator from unsigned integer
	 *
	 * @param val is the unsigned integer value that is assigned.
	 * @return the assigned Big Binary Integer ref.
	 */
	const NativeInteger& operator=(const uint_type& val) {
		this->m_value = val;
		return *this;
	}

	//Shift Operators

	/**
	 * Left shift operator of big binary integer
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	NativeInteger  operator<<(usshort shift) const {
		return NativeInteger( m_value << shift );
	}

	/**
	 * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
	 *
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	const NativeInteger&  operator<<=(usshort shift) {
		m_value <<= shift;
		return *this;
	}

	/**
	 * Right shift operator of big binary integer
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	NativeInteger  operator>>(usshort shift) const {
		return NativeInteger( m_value >> shift );
	}

	/**
	 * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
	 *
	 * @param shift is the amount to shift of type usshort.
	 * @return the object of type NativeInteger
	 */
	NativeInteger&  operator>>=(usshort shift) {
		m_value >>= shift;
		return *this;
	}

	//Auxillary Functions

	/**
	 * Prints the value to console in base-r format where r is equal to 2^bitwidth of the integral datatype.
	 */
	void PrintValueInDec() const {
		std::cout << std::dec << m_value << std::endl;
	}

	/**
	 * Basic set method for setting the value of a big binary integer
	 *
	 * @param str is the string representation of the big binary integer to be copied.
	 */
	void SetValue(const std::string& str) {
		AssignVal(str);
	}

	/**
	 * Basic set method for setting the value of a big binary integer
	 *
	 * @param a is the big binary integer representation of the big binary integer to be assigned.
	 */
	void SetValue(const NativeInteger& a) {
		m_value = a.m_value;
	}


	/**
	 * Returns the MSB location of the value.
	 *
	 * @return the index of the most significant bit.
	 */
	usshort GetMSB() const { return GetMSB32(this->m_value); }

	/**
	 * Converts the value to an int.
	 *
	 * @return the int representation of the value as usint.
	 */
	uint64_t ConvertToInt() const {
		return m_value;
	}

	/**
	 * Converts the value to an double.
	 *
	 * @return double representation of the value.
	 */
	double ConvertToDouble() const {
		return m_value;
	}

	/**
	 * Convert a value from an int to a BigBinaryInt.
	 *
	 * @param m the value to convert from.
	 * @return int represented as a big binary int.
	 */
	static NativeInteger intToNativeInteger(usint m) {
		return NativeInteger(m);
	}

	//Arithemetic Operations

	/**
	 * Addition operation.
	 *
	 * @param b is the value to add of type Big Binary Integer.
	 * @return result of the addition operation of type BigBinary Integer.
	 */
	NativeInteger Plus(const NativeInteger& b) const {
		return m_value + b.m_value;
	}


	/**
	 * Addition accumulator.
	 *
	 * @param &b is the value to add of type Big Binary Integer.
	 * @return result of the addition operation of type Big Binary Integer.
	 */
	const NativeInteger& operator+=(const NativeInteger &b) {
		m_value += b.m_value;
		return *this;
	}


	/**
	 * Subtraction accumulator.
	 *
	 * @param &b is the value to subtract of type Big Binary Integer.
	 * @return result of the subtraction operation of type Big Binary Integer.
	 */
	const NativeInteger& operator-=(const NativeInteger &b) {
		if( m_value <= b.m_value )
			m_value = 0;
		else
			m_value -= b.m_value;
		return *this;
	}

	/**
	 * Subtraction operation.
	 *
	 * @param b is the value to subtract of type Big Binary Integer.
	 * @return result of the subtraction operation of type Big Binary Integer.
	 */
	NativeInteger Minus(const NativeInteger& b) const {
		return m_value <= b.m_value ? 0 : m_value - b.m_value;
	}


	/**
	 * Multiplication operation.
	 *
	 * @param b of type Big Binary Integer is the value to multiply with.
	 * @return result of the multiplication operation.
	 */
	NativeInteger Times(const NativeInteger& b) const {
		return this->m_value * b.m_value;
	}

	/**
	 * Division operation.
	 *
	 * @param b of type NativeInteger is the value to divide by.
	 * @return result of the division operation.
	 */
	NativeInteger DividedBy(const NativeInteger& b) const {
		return this->m_value / b.m_value;
	}

	//modular arithmetic operations

	/**
	 * returns the modulus with respect to the input value. Classical modular reduction algorithm is used.
	 *
	 * @param modulus is value of the modulus to perform. Its of type NativeInteger.
	 * @return NativeInteger that is the result of the modulus operation.
	 */
	NativeInteger Mod(const NativeInteger& modulus) const {
		return m_value % modulus.m_value;
	}

	/**
	 * returns the modulus with respect to the input value.
	 * Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
	 * See the cpp file for details of the implementation.
	 *
	 * @param modulus is the modulus to perform.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus operation.
	 */
	NativeInteger ModBarrett(const NativeInteger& modulus, const NativeInteger& mu) const {
		return this->m_value%modulus.m_value;
	}

	/**
	* returns the modulus with respect to the input value - In place version.
	* Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
	* See the cpp file for details of the implementation.
	*
	* @param modulus is the modulus to perform.
	* @param mu is the Barrett value.
	* @return is the result of the modulus operation.
	*/
	void ModBarrettInPlace(const NativeInteger& modulus, const NativeInteger& mu) {
		this->m_value %= modulus.m_value;
		return;
	}

	/**
	 * returns the modulus with respect to the input value.
	 * Implements generalized Barrett modular reduction algorithm. Uses an array of precomputed values \mu.
	 * See the cpp file for details of the implementation.
	 *
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return result of the modulus operation.
	 */
	NativeInteger ModBarrett(const NativeInteger& modulus, const NativeInteger mu_arr[BARRETT_LEVELS+1]) const {
		return this->m_value%modulus.m_value;
	}

	/**
	 * returns the modulus inverse with respect to the input value.
	 *
	 * @param modulus is the modulus to perform.
	 * @return result of the modulus inverse operation.
	 */
	NativeInteger ModInverse(const NativeInteger& mod) const {

		uint_type result = 0;
		uint_type modulus = mod.m_value;

		std::vector<uint_type> mods;
		std::vector<uint_type> quotient;
		mods.push_back(modulus);
		if (this->m_value > modulus)
			mods.push_back(this->m_value%modulus);
		else
			mods.push_back(this->m_value);

		uint_type first(mods[0]);
		uint_type second(mods[1]);
		if(mods[1]==1){
			result = 1;
			return result;
		}

		//Error if modulus is ZERO
		if(this->m_value == 0) {
			throw std::logic_error("Zero does not have a ModInverse");
		}


		//NORTH ALGORITHM
		while(true){
			mods.push_back(first%second);
			quotient.push_back(first/second);
			if(mods.back()==1)
				break;
			if(mods.back()==0){
				std::string msg = std::to_string(m_value) + " does not have a ModInverse using " + std::to_string(modulus);
				throw std::logic_error(msg);
			}

			first = second;
			second = mods.back();
		}

		mods.clear();
		mods.push_back(0);
		mods.push_back(1);

		first = mods[0];
		second = mods[1];

		//SOUTH ALGORITHM
		for(sint i=quotient.size()-1;i>=0;i--){
			mods.push_back(quotient[i]*second + first);
			first = second;
			second = mods.back();
		}


		if(quotient.size()%2==1){
			result = (modulus - mods.back());
		}
		else{
			result = mods.back();
		}

		return result;
	}

	/**
	 * Scalar modular addition.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus addition operation.
	 */
	NativeInteger ModAdd(const NativeInteger& b, const NativeInteger& modulus) const {
		return this->Plus(b).Mod(modulus);
	}

	/**
	 * Modular addition where Barrett modulo reduction is used.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus addition operation.
	 */
	NativeInteger ModBarrettAdd(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->Plus(b).ModBarrett(modulus,mu_arr);
	}

	/**
	 * Modular addition where Barrett modulo reduction is used.
	 *
	 * @param &b is the scalar to add.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is one precomputed Barrett value.
	 * @return is the result of the modulus addition operation.
	 */
	NativeInteger ModBarrettAdd(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger& mu) const {
		return this->Plus(b).ModBarrett(modulus,mu);
	}

	/**
	 * Scalar modular subtraction.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @return result of the modulus subtraction operation.
	 */
	NativeInteger ModSub(const NativeInteger& b, const NativeInteger& mod) const {
		uint_type av = this->m_value;
		uint_type bv = b.m_value;
		uint_type modulus = mod.m_value;

		//reduce this to a value lower than modulus
		if(av > modulus) {
			av %= modulus;
		}
		//reduce b to a value lower than modulus
		if(bv > modulus){
			bv %= modulus;
		}

		if(av >= bv){
			return (av-bv)%modulus;
		}
		else{
			return (av + modulus) - bv;
		}
	}

	/**
	 * Scalar modular subtraction where Barrett modular reduction is used.
	 *
	 * @param &b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the Barrett value.
	 * @return is the result of the modulus subtraction operation.
	 */
	NativeInteger ModBarrettSub(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) const {
		return this->ModSub(b,modulus);
	}

	/**
	 * Scalar modular subtraction where Barrett modular reduction is used.
	 *
	 * @param b is the scalar to subtract.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus subtraction operation.
	 */
	NativeInteger ModBarrettSub(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->ModSub(b,modulus);
	}

	/**
	 * Scalar modulus multiplication.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModMul(const NativeInteger& b, const NativeInteger& modulus) const {
		uint_type av = this->m_value;
		uint_type bv = b.m_value;

		if( av > modulus.m_value ) av = av%modulus.m_value;
		if( bv > modulus.m_value ) bv = bv%modulus.m_value;

		return NativeInteger((av*bv)%modulus.m_value);
	}

	/**
	 * Scalar modular multiplication where Barrett modular reduction is used.
	 * Implements generalized Barrett modular reduction algorithm (no interleaving between multiplication and modulo).
	 * Uses one precomputed value \mu.
	 * See the cpp file for details of the implementation.
	 *
	 * @param b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu is the precomputed Barrett value.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModBarrettMul(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger& mu) const {
		return this->ModMul(b,modulus);
	}

	/**
	* Scalar modular multiplication where Barrett modular reduction is used - In-place version
	* Implements generalized Barrett modular reduction algorithm (no interleaving between multiplication and modulo).
	* Uses one precomputed value \mu.
	* See the cpp file for details of the implementation.
	*
	* @param b is the scalar to multiply.
	* @param modulus is the modulus to perform operations with.
	* @param mu is the precomputed Barrett value.
	* @return is the result of the modulus multiplication operation.
	*/
	void ModBarrettMulInPlace(const NativeInteger& b, const NativeInteger& modulus, const NativeInteger& mu) {
		*this = this->ModMul(b,modulus);
		return;
	}

	/**
	 * Scalar modular multiplication where Barrett modular reduction is used.
	 *
	 * @param &b is the scalar to multiply.
	 * @param modulus is the modulus to perform operations with.
	 * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
	 * @return is the result of the modulus multiplication operation.
	 */
	NativeInteger ModBarrettMul(const NativeInteger& b, const NativeInteger& modulus,const NativeInteger mu_arr[BARRETT_LEVELS]) const {
		return this->ModMul(b,modulus);
	}

	/**
	 * Scalar modular exponentiation. Square-and-multiply algorithm is used.
	 *
	 * @param &b is the scalar to exponentiate.
	 * @param modulus is the modulus to perform operations with.
	 * @return is the result of the modulus exponentiation operation.
	 */
	NativeInteger ModExp(const NativeInteger& b, const NativeInteger& mod) const {
		uint_type modulus = mod.m_value;
		uint_type exp = b.m_value;
		uint_type product = 1;
		uint_type mid = m_value%modulus;

		while( true ) {
			if( exp%2 == 1 )
				product *= mid;

			//running product is calculated
			if(product>modulus){
				product %= modulus;
			}

			//divide by 2 and check even to odd to find bit value
			exp >>= 1;
			if(exp == 0)
				break;

			//mid calculates mid^2%q
			mid = mid*mid;

			mid %= modulus;
		}
		return product;
	}

	/**
	 * Stores the based 10 equivalent/Decimal value of the NativeInteger in a string object and returns it.
	 *
	 * @return value of this NativeInteger in base 10 represented as a string.
	 */
	const std::string ToString() const {
		std::stringstream ss;
		ss << m_value;
		return ss.str();
	}

	// Serialize using the modulus; convert value to signed, the serialize
	const std::string Serialize(const NativeInteger& modulus = 0) const {
		static char to_base64_char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		// numbers go from high to low -1, -2, ... +modulus/2, modulus/2 - 1, ... ,1, 0
		bool isneg = false;
		NativeInteger signedVal;
		if( modulus.m_value == 0 || m_value < modulus.m_value/2 )
			signedVal = m_value;
		else {
			signedVal = modulus.m_value - m_value;
			isneg = true;
		}

		std::string ser = "";
		if( isneg ) ser += "-";
		usint len = signedVal.GetMSB();
		ser += to_base64_char[len];
		for( int i=len; i>0; i-=6 )
			ser += to_base64_char[signedVal.Get6BitsAtIndex(i)];
		return ser;
	}

	static inline unsigned char base64_to_value(unsigned char b64) {
		if( isupper(b64) )
			return b64 - 'A';
		else if( islower(b64) )
			return b64 - 'a' + 26;
		else if( isdigit(b64) )
			return b64 - '0' + 52;
		else if( b64 == '+' )
			return 62;
		else
			return 63;
	}

	const char * Deserialize(const char * str, const NativeInteger& modulus = 0) {
		bool isneg = false;
		if( *str == '-' ) {
			++str;
			isneg = true;
		}
		usint len = base64_to_value(*str);
		uint64_t value = 0;

		for( ; len > 6 ; len -= 6 )
			value = (value<<6)|base64_to_value(*++str);

		if( len )
			value = (value<<len) | (base64_to_value(*++str));// >> (6-len));

		if( isneg )
			value = (modulus.m_value - value);

		m_value = value;
		return str;
	}


	/**
	 * Tests whether the NativeInteger is a power of 2.
	 *
	 * @param m_numToCheck is the value to check.
	 * @return true if the input is a power of 2, false otherwise.
	 */
	bool CheckIfPowerOfTwo(const NativeInteger& m_numToCheck);

	/**
	 * Get the number of digits using a specific base - support for arbitrary base may be needed.
	 *
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetLengthForBase(usint base) const {return GetMSB();}

	/**
	 * Get the number of digits using a specific base - only power-of-2 bases are currently supported.
	 *
	 * @param index is the location to return value from in the specific base.
	 * @param base is the base with which to determine length in.
	 * @return the length of the representation in a specific base.
	 */
	usint GetDigitAtIndexForBase(usint index, usint base) const {

			usint digit = 0;
			usint newIndex = index;
			for (usint i = 1; i < base; i = i*2)
			{
				//std::cout << m_value << ", " << newIndex  << ", " << " " << (uint8_t)GetBitAtIndex(newIndex) << std::endl;
				digit += GetBitAtIndex(newIndex)*i;
				newIndex++;
			}
			return digit;
	}

	/**
	 * Convert a string representation of a binary number to a decimal BigBinaryInt.
	 *
	 * @param bitString the binary num in string.
	 * @return the binary number represented as a big binary int.
	 */
	static NativeInteger BinaryStringToBigBinaryInt(const std::string& bitString) {
		if( bitString.length() > m_uintBitLength ) {
			throw std::logic_error("bit string is too long to fit");
		}

		uint_type v = 0;
		for( int i=0 ; i < bitString.length() ; i++ ) {
			int n = bitString[i] - '0';
			if( n < 0 || n > 1 ) {
				throw std::logic_error("bit string must contain only 0 or 1");
			}

			v <<= 1;
			v |= n;
		}

		return v;
	}

	/**
	 * Exponentiation of a bigBinaryInteger x. Returns x^p
	 *
	 * @param p the exponent.
	 * @return the big binary integer x^p.
	 */
	NativeInteger Exp(usint p) const {
		if (p == 0) return 1;
		NativeInteger x = this->m_value;
		if (p == 1) return x;

		NativeInteger tmp = x.Exp(p/2);
		if (p%2 == 0) return tmp * tmp;
		else return tmp * tmp * x;
	}

	/**
	 * Multiply and Rounding operation on a bigBinaryInteger x. Returns [x*p/q] where [] is the rounding operation.
	 *
	 * @param p is the numerator to be multiplied.
	 * @param q is the denominator to be divided.
	 * @return the result of multiply and round.
	 */
	NativeInteger MultiplyAndRound(const NativeInteger &p, const NativeInteger &q) const {
		NativeInteger ans = m_value*p.m_value;
		return ans.DivideAndRound(q);
	}

	/**
	 * Divide and Rounding operation on a bigBinaryInteger x. Returns [x/q] where [] is the rounding operation.
	 *
	 * @param q is the denominator to be divided.
	 * @return the result of divide and round.
	 */
	NativeInteger DivideAndRound(const NativeInteger &q) const {

		uint_type ans = m_value/q.m_value;
		uint_type rem = m_value%q.m_value;
		uint_type halfQ = q.m_value >> 1;

		//Rounding operation from running remainder
		if (!(rem <= halfQ)) {
			ans += 1;
		}

		return ans;
	}

	/**
	 * Test equality of the inputs.
	 *
	 * @param a second value to test.
	 * @return true if the inputs are equal.
	 */
	bool operator==(const NativeInteger& a) const { return m_value == a.m_value; }

	/**
	 * Test inequality of the inputs.
	 *
	 * @param a second value to test.
	 * @return true if the inputs are inequal.
	 */
	bool operator!=(const NativeInteger& a) const { return m_value != a.m_value; }

	/**
	 * Test if first input is great than the second input.
	 *
	 * @param a second value to test.
	 * @return true if the first inputs is greater.
	 */
	bool operator> (const NativeInteger& a) const { return m_value > a.m_value; }

	/**
	 * Test if first input is great than or equal to the second input.
	 *
	 * @param a second value to test.
	 * @return true if the first inputs is greater than or equal to the second input.
	 */
	bool operator>=(const NativeInteger& a) const { return m_value >= a.m_value; }

	/**
	 * Test if first input is less than the second input.
	 *
	 * @param a second value to test.
	 * @return true if the first inputs is lesser.
	 */
	bool operator< (const NativeInteger& a) const { return m_value < a.m_value; }

	/**
	 * Test if first input is less than or equal to the second input.
	 *
	 * @param a second value to test.
	 * @return true if the first inputs is less than or equal to the second input.
	 */
	bool operator<=(const NativeInteger& a) const { return m_value <= a.m_value; }

	//overloaded binary operators based on integer arithmetic and comparison functions
	/**
	 * Addition operation.
	 *
	 * @param a is the value to add.
	 * @return is the result of the addition operation.
	 */
	inline NativeInteger operator+(const NativeInteger &a) const {return this->Plus(a);}

	/**
	 * Subtraction operation.
	 *
	 * @param a is the value to subtract.
	 * @return is the result of the subtraction operation.
	 */
	inline NativeInteger operator-(const NativeInteger &a) const {return this->Minus(a);}

	/**
	 * Multiplication operation.
	 *
	 * @param a is the value to multiply with.
	 * @return is the result of the multiplication operation.
	 */
	inline NativeInteger operator*(const NativeInteger &a) const {return this->Times(a);}

	/**
	 * Modulo operation. Classical modular reduction algorithm is used.
	 *
	 * @param a is the value to Mod.
	 * @return is the result of the modulus operation.
	 */
	inline NativeInteger operator%(const NativeInteger &a) const {return this->Mod(a);}

	/**
	 * Division operation.
	 *
	 * @param a is the value to divide.
	 * @param b is the value to divide by.
	 * @return is the result of the integral part after division operation.
	 */
	inline NativeInteger operator/ (const NativeInteger &a) const {return this->DividedBy(a);}

	/**
	 * Console output operation.
	 *
	 * @param os is the std ostream object.
	 * @param ptr_obj is NativeInteger to be printed.
	 * @return is the ostream object.
	 */
	template<typename uint_type_c>
	friend std::ostream& operator<<(std::ostream& os, const NativeInteger<uint_type_c> &ptr_obj) {
		os << ptr_obj.m_value;
		return os;
	}

	/**
	 * Gets the bit at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return resulting bit.
	 */
	uschar GetBitAtIndex(usint index) const {
		if(index==0) {
			throw std::logic_error("Zero index in GetBitAtIndex");
		}

		return (m_value >> (index-1)) & 0x01;
	}

	/**
	 * Gets the bit at the specified index.
	 *
	 * @param index is the index of the bit to get.
	 * @return resulting bit.
	 */
	uschar Get6BitsAtIndex(usint index) const {
		static unsigned char smallmask[] = { 0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f };

		if(index==0) {
			throw std::logic_error("Zero index in GetBitAtIndex");
		}
		if( index<=6 ) {
			return m_value & smallmask[index];
		}

		return (m_value >> (index-6)) & 0x3f;
	}


	/**
	 * Sets the int value at the specified index.
	 *
	 * @param index is the index of the int to set in the uint array.
	 */
	void SetIntAtIndex(usint idx, uint_type value);

	//constant definations

	/**
	 * Constant zero.
	 */
	static const NativeInteger ZERO;

	/**
	 * Constant one.
	 */
	static const NativeInteger ONE;

	/**
	 * Constant two.
	 */
	static const NativeInteger TWO;

	/**
	 * Constant three.
	 */
	static const NativeInteger THREE;

	/**
	 * Constant four.
	 */
	static const NativeInteger FOUR;

	/**
	 * Constant five.
	 */
	static const NativeInteger FIVE;

	/**
	 * Compares the current NativeInteger to NativeInteger a.
	 *
	 * @param a is the NativeInteger to be compared with.
	 * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
	 */
	sint Compare(const NativeInteger& a) const {
		if( this->m_value < a.m_value )
			return -1;
		else if( this->m_value > a.m_value )
			return 1;
		return 0;
	}

	/**
	 *  Set this int to 1.
	 *  Note some compilers don't like using the ONE constant, above :(
	 */
	inline void SetIdentity() { *this = NativeInteger<uint_type>(1); };

	/**
	 * A zero allocator that is called by the Matrix class. It is used to initialize a Matrix of NativeInteger objects.
	 */
	static std::function<unique_ptr<NativeInteger<uint_type>>()> Allocator;

protected:

	/**
	 * Converts the string v into base-r integer where r is equal to 2^bitwidth of integral data type.
	 *
	 * @param v The input string
	 */
	void AssignVal(const std::string& str) {
		m_value = 0;
		for( int i=0; i<str.length(); i++ ) {
			int v = str[i] - '0';
			if( v < 0 || v > 9 ) {
				throw std::logic_error("string contains a non-digit");
			}
			m_value *= 10;
			m_value += v;
		}
	}

private:

	// representation as a
	uint_type m_value;

	//variable to store the bit width of the integral data type.
	static const uschar m_uintBitLength = sizeof(uint_type)*8;

	//variable to store the maximum value of the integral data type.
	static const uint_type m_uintMax = std::numeric_limits<uint_type>::max();

	//variable to store the log(base 2) of the number of bits in the integral data type.
	static const uschar m_logUintBitLength = LogDtype<uint_type>::value;

	/**
	 * function to return the ceiling of the number divided by the number of bits in the integral data type.
	 * @param Number is the number to be divided.
	 * @return the ceiling of Number/(bits in the integral data type)
	 */
	static uint_type ceilIntByUInt(const uint_type Number) {
		//mask to perform bitwise AND
		static uint_type mask = m_uintBitLength-1;

		if((Number&mask)!=0)
			return (Number>>m_logUintBitLength)+1;
		else if(!Number)
			return 1;
		else
			return Number>>m_logUintBitLength;
	}

	/**
	 * function to return the MSB of a 32 bit number.
	 * @param x is the 32 bit integer.
	 * @return the MSB position in the 32 bit number x.
	 */

	static uint64_t GetMSB32(uint64_t x)
	{
	    static const usint bval[] =
	    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

	    uint64_t r = 0;
		if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
	    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
	    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
		if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
	    return r + bval[x];
	}

	/**
	 * function to return the MSB of number.
	 * @param x is the number.
	 * @return the MSB position in the number x.
	 */

	static uint_type GetMSBUint_type(uint_type x) { return GetMSB32(x); }

	//Duint_type is the data type that has twice as many bits in the integral data type.
	typedef typename DoubleDataType<uint_type>::T Duint_type;

	/**
	 * function that returns the NativeInteger after multiplication by b.
	 * @param b is the number to be multiplied.
	 * @return the NativeInteger after the multiplication.
	 */
	NativeInteger MulIntegerByChar(uint_type b) const;

	/**
	* function that returns the NativeInteger after multiplication by b.
	* @param b is the number to be multiplied.
	* @return the NativeInteger after the multiplication.
	*/
	void MulIntegerByCharInPlace(uint_type b, NativeInteger *ans);

	/**
	 * function that returns the decimal value from the binary array a.
	 * @param a is a pointer to the binary array.
	 * @return the decimal value.
	 */
	static uint_type UintInBinaryToDecimal(uschar *a);

	/**
	 * function that mutiplies by 2 to the binary array.
	 * @param a is a pointer to the binary array.
	 */
	static void double_bitVal(uschar *a);

	/**
	 * function that adds bit b to the binary array.
	 * @param a is a pointer to the binary array.
	 * @param b is a bit value to be added.
	 */
	static void add_bitVal(uschar* a,uschar b);
};

}//namespace ends

#endif
