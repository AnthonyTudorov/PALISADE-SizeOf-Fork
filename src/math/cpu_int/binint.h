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
 * This file contains the vector manipulation functionality.
 */

#ifndef LBCRYPTO_MATH_CPUINT_BININT_H
#define LBCRYPTO_MATH_CPUINT_BININT_H

#include <iostream>
#include <string>
#include <vector>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <limits>
#include <fstream>
#include <stdexcept>

 #include "../../utils/inttypes.h"

/**
*@namespace cpu_int
* The namespace of cpu_int
*/
namespace cpu_int{

        /*
         *Struct to Assign Value
         *
         */
	template <usint N>
	struct log2{
		const static usint value = 1 + log2<N/2>::value;
	};
    
        /*
        *Struct to assign value to 1
        *
        */
	template<>
	struct log2<2>{
		const static usint value = 1;
	};
    
        /*
        *Struct to assign value
        *
        */
	template <typename U>
	struct logdtype{
		const static usint value = log2<8*sizeof(U)>::value;
	};
    
        /*
         *???
         *
         */
	template<typename dtype>
	struct datatypechecker{
		// const static bool value = false ;
		//NP-TODO - This boolean check does not work in Linux. 
		const static bool value = true ;
		static_assert(value,"Data type provided is not supported in BigBinaryInteger");
	};

        /**
         *Structure for checking datatype
         * @Return Returns bool true if datatype is unsigned integer 8 bit.
         */
	template<>
	struct datatypechecker<uint8_t>{
		const static bool value = true ;	
	};
        /**
        *Structure for checking datatype
         * @Return Returns bool true if datatype is unsigned integer 16 bit.
         */
	template<>
	struct datatypechecker<uint16_t>{
		const static bool value = true ;	
	};
        /**
         *Structure for checking datatype
         * @Return Returns bool true if datatype is unsigned integer 32 bit.
         */
	template<>
	struct datatypechecker<uint32_t>{
		const static bool value = true ;	
	};
        /**
         *Structure for checking datatype
         * @Return Returns bool true if datatype is unsigned integer 64 bit.
         */
	template<>
	struct datatypechecker<uint64_t>{
		const static bool value = true ;	
	};

	/*
	BBI should have a bitlength of datatype
	BBI should have a log of bitlength of datatype
	BBI should have a double datatype
	BBI should have a function that calculates the MSB in datatype
	BBI should have a function that calculates the MSB in doubledatatype
	*/

	template <typename uint_type>
	struct uintBitWidth{
		static_assert(datatypechecker<uint_type>::value,"Data type provided is not supported in BigBinaryInteger");
		const static int value = 8*sizeof(uint_type);
	};
        /*
         * ???
         */
	template<typename utype>
	struct doubleDataType{
		typedef void T;
	};

        /*
         * Datatype double template function
         * sets T as of type unsigned integer 16 bit if initial datatype is 8bit
         */
	template<>
	struct doubleDataType<uint8_t>{
		typedef uint16_t T;
	};
        /*
         * Datatype double template function
         * sets T as of type unsigned integer 32 bit if initial datatype is 16bit
         */
    template<>
	struct doubleDataType<uint16_t>{
		typedef uint32_t T;
	};
        /*
         * Datatype double template function
         * sets T as of type unsigned integer 64 bit if initial datatype is 32bit
         */
	template<>
	struct doubleDataType<uint32_t>{
		typedef uint64_t T;
	};


	const usint NUM_DIGIT_IN_PRINTVAL = 45;	//!< @brief The maximum number of digits in bigbinaryinteger. It is used by the cout(ostream) function for printing the bigbinarynumber.
    const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.
    const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels used in the Barrett reductions.

	template<typename uint_type,usint BITLENGTH>
	class BigBinaryInteger
	{

	public:

        /**
         * Basic constructor.
         */
    BigBinaryInteger();
        /**
        * Basic constructor for specifying the integer.
        *
        * @param str is the initial integer represented as a string.
        */
    explicit BigBinaryInteger(const std::string& str);
        /**
        * Basic constructor for initializing big binary integer from an unsigned integer.
        *
        * @param init is the initial integer.
        */
    explicit BigBinaryInteger(usint init);
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
        * Destructor.
        */
    ~BigBinaryInteger();
        
        /**
        * Copy constructor
        *
        * @param &rhs is the big binary matrix to test equality with.
        * @return the return value.
        */
    BigBinaryInteger&  operator=(const BigBinaryInteger &rhs);
        /**
         * Move copy constructor
         *
         * @param &&rhs is the big binary matrix to test equality with.
         * @return the return value.
         */
    BigBinaryInteger&  operator=(BigBinaryInteger &&rhs);

//Shift Operators
        /**
         * Left shift operator of big binary integer
         * @param shift is the amount to shift of type usshort.
         * @return the object of type BigBinaryInteger
        **/
	BigBinaryInteger  operator<<(usshort shift) const;

        /**
         * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
         *
         * @param shift is the amount to shift of type usshort.
         * @return the object of type BigBinaryInteger
         */
    BigBinaryInteger&  operator<<=(usshort shift);
        
        /**
         * Right shift operator of big binary integer
         * @param shift is the amount to shift of type usshort.
         * @return the object of type BigBinaryInteger
         **/
    BigBinaryInteger  operator>>(usshort shift) const;

        /**
         * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
         *
         * @param shift is the amount to shift of type usshort.
         * @return the object of type BigBinaryInteger
         */
    BigBinaryInteger&  operator>>=(usshort shift);

//Auxillary Functions
        /**
         * Prints the value to stdout in decimal format.
         */
    void PrintValueInDec() const;

        /**
         * Basic set method for setting the value of a big binary integer
         *
         * @param str is the string representation of the big binary integer to be copied.
         * @returns nothing
         */
    void SetValue(const std::string& str);
        
        /**
         * Basic set method for setting the value of a big binary integer
         *
         * @param a is the big binary integer representation of the big binary integer to be copied.
         * @returns nothing
         */
    void SetValue(const BigBinaryInteger& a);

        
        /**
         * Returns the MSB location of the value.
         *
         * @return the index of the most significant bit.
         */
    usshort GetMSB()const;

        /**
         * Returns the index number of the array in which MSB is located.
         *
         * @return the index of array of the most significant bit as usshort.
         */
    usshort GetMSBCharNum()const;

        /**
         * Convert the value to an int.
         *
         * @return the int representation of the value as usint.
         */
    usint ConvertToInt() const;
    
    double ConvertToDouble() const;

//Arithemetic Operations
        /**
         * Addition operation.
         *
         * @param b is the value to add of type Big Binary Integer.
         * @return is the result of the addition operation of type BigBinary Integer.
         */
    BigBinaryInteger Plus(const BigBinaryInteger& b) const;

		
        /**
         * Addition accumulator.
         *
         * @param &b is the value to add of type Big Binary Integer.
         * @return is the result of the addition operation of type Big Binary Integer.
         */
    const BigBinaryInteger& operator+=(const BigBinaryInteger &b);

		
        /**
         * Subtraction accumulator.
         *
         * @param &b is the value to subtract of type Big Binary Integer.
         * @return is the result of the subtraction operation of type Big Binary Integer.
         */
    const BigBinaryInteger& operator-=(const BigBinaryInteger &b);

        /**
         * Subtraction operation.
         *
         * @param b is the value to subtract of type Big Binary Integer.
         * @return is the result of the subtraction operation of type Big Binary Integer.
         */
    BigBinaryInteger Minus(const BigBinaryInteger& b) const;

        
        /**
         * Multiplication operation.
         *
         * @param b of type Big Binary Integer is the value to multiply with.
         * @return is the result of the multiplication operation.
         */
    BigBinaryInteger Times(const BigBinaryInteger& b) const;

        /**
         * Division operation.
         *
         * @param b of type BigBinaryInteger is the value to divide by.
         * @return is the result of the division operation.
         */
    BigBinaryInteger DividedBy(const BigBinaryInteger& b) const;

//modular arithmetic operations
		
        /**
         * returns the modulus with respect to the input value.
         *
         * @param modulus is value of the modulus to perform. Its of type BigBinaryInteger.
         * @returns a BigBinaryInteger that is the result of the modulus operation.
         */
    BigBinaryInteger Mod(const BigBinaryInteger& modulus) const;
    
        /**
         * returns the Barret modulus with respect to the input modulus and the Barrett value.
         *
         * @param modulus is the modulus to perform.
         * @param mu is the Barrett value.
         * @return is the result of the modulus operation.
         */
    BigBinaryInteger ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const;

        /**
         * returns the Barret modulus with respect to the input modulus and the Barrett value.
         *
         * @param modulus is the modulus to perform operations with.
         * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
         * @return is the result of the modulus operation.
         */
    BigBinaryInteger ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS+1]) const;

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
    BigBinaryInteger ModAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

        /**
         * Scalar Barrett modulus addition.
         *
         * @param &b is the scalar to add.
         * @param modulus is the modulus to perform operations with.
         * @param mu is the Barrett value.
         * @return is the result of the modulus addition operation.
         */
    BigBinaryInteger ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const;

        /**
         * Scalar Barrett modulus addition.
         *
         * @param &b is the scalar to add.
         * @param modulus is the modulus to perform operations with.
         * @param mu is an array of the Barrett values of length BARRETT_LEVELS.
         * @return is the result of the modulus addition operation.
         */
    BigBinaryInteger ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

        /**
         * Scalar modulus subtraction.
         *
         * @param &b is the scalar to subtract.
         * @param modulus is the modulus to perform operations with.
         * @return is the result of the modulus subtraction operation.
         */
    BigBinaryInteger ModSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

        /**
         * Scalar Barrett modulus subtraction.
         *
         * @param &b is the scalar to subtract.
         * @param modulus is the modulus to perform operations with.
         * @param mu is the Barrett value.
         * @return is the result of the modulus subtraction operation.
         */
    BigBinaryInteger ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

        /**
         * Scalar Barrett modulus subtraction.
         *
         * @param b is the scalar to subtract.
         * @param modulus is the modulus to perform operations with.
         * @param mu is an array of the Barrett values of length BARRETT_LEVELS.
         * @return is the result of the modulus subtraction operation.
         */
    BigBinaryInteger ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const;

        /**
         * Scalar modulus multiplication.
         *
         * @param &b is the scalar to multiply.
         * @param modulus is the modulus to perform operations with.
         * @return is the result of the modulus multiplication operation.
         */

    BigBinaryInteger ModMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

        /**
         * Scalar Barrett modulus multiplication.
         *
         * @param b is the scalar to multiply.
         * @param modulus is the modulus to perform operations with.
         * @param mu is the Barrett value.
         * @return is the result of the modulus multiplication operation.
         */
    BigBinaryInteger ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

        /**
         * Scalar Barrett modulus multiplication.
         *
         * @param &b is the scalar to multiply.
         * @param modulus is the modulus to perform operations with.
         * @param mu is an array of the Barrett values of length BARRETT_LEVELS.
         * @return is the result of the modulus multiplication operation.
         */
    BigBinaryInteger ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const;

        /**
         * Scalar modulus exponentiation.
         *
         * @param &b is the scalar to exponentiate at all locations.
         * @param modulus is the modulus to perform operations with.
         * @return is the result of the modulus exponentiation operation.
         */
    BigBinaryInteger ModExp(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

        /**
         * Stores the value of this BigBinaryInteger in a string object and returns it.
         * Added by Arnab Deb Gupta <ad479@njit.edu> on 9/21/15 templated bt Gyana Sahu 12/23/2015
         *
         * @return the value of this BigBinaryInteger as a string.
         */

    const std::string ToString() const;

		//template<typename uint_type,usint BITLENGTH>
		//friend bool CheckPowerofTwos(const BigBinaryInteger<uint_type,BITLENGTH>& m_numToCheck);

        /**
         * Tests whether the value is a power of 2.
         *
         * @param m_numToCheck is the value to check.
         * @return true if the input is a power of 2, false otherwise.
         */
    bool CheckPowerofTwos(const BigBinaryInteger& m_numToCheck);

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

        /**
         * Test equality of the inputs.
         *
         * @param a second value to test.
         * @return true if the inputs are equal.
         */
    bool operator==(const BigBinaryInteger& a) const;
        /**
         * Test inequality of the inputs.
         *
         * @param a second value to test.
         * @return true if the inputs are inequal.
         */
    bool operator!=(const BigBinaryInteger& a) const;
        /**
         * Test if first input is great than the second input.
         *
         * @param a second value to test.
         * @return true if the first inputs is greater.
         */
    bool operator> (const BigBinaryInteger& a) const;
        /**
         * Test if first input is great than or equal to the second input.
         *
         * @param a second value to test.
         * @return true if the first inputs is greater than or equal to the second input.
         */
    bool operator>=(const BigBinaryInteger& a) const;
        /**
         * Test if first input is less than the second input.
         *
         * @param a second value to test.
         * @return true if the first inputs is lesser.
         */
    bool operator< (const BigBinaryInteger& a) const;
        /**
         * Test if first input is less than or equal to the second input.
         *
         * @param a second value to test.
         * @return true if the first inputs is less than or equal to the second input.
         */
    bool operator<=(const BigBinaryInteger& a) const;

        //overloaded binary operators based on integer arithmetic and comparison functions
        /**
         * Addition operation.
         *
         * @param a is the value to add.
         * @return is the result of the addition operation.
         */
    inline BigBinaryInteger operator+(const BigBinaryInteger &a) const {return this->Plus(a);}
        /**
         * Subtraction operation.
         *
         * @param a is the value to subtract.
         * @return is the result of the subtraction operation.
         */
    inline BigBinaryInteger operator-(const BigBinaryInteger &a) const {return this->Minus(a);}
        /**
         * Multiplication operation.
         *
         * @param a is the value to multiply with.
         * @return is the result of the multiplication operation.
         */
    inline BigBinaryInteger operator*(const BigBinaryInteger &a) const {return this->Times(a);}
        /**
         * Division operation.
         *
         * @param a is the value to divide.
         * @return is the result of the division operation.
         */
    inline BigBinaryInteger operator%(const BigBinaryInteger &a) const {return this->Mod(a);}

    template<typename uint_type_c,usint BITLENGTH_c>
		friend std::ostream& operator<<(std::ostream& os, const BigBinaryInteger<uint_type_c,BITLENGTH_c> &ptr_obj);
        /**
         * Gets the bit at the specified index.
         *
         * @param index is the index of the bit to get.
         * @return is the resulting bit.
         */
    uschar GetBitAtIndex(usint index) const;

        
        //constant definations
        
        /**
         * Constant zero.
         */
    static const BigBinaryInteger ZERO;
        /**
         * Constant one.
         */
    static const BigBinaryInteger ONE;
        /**
         * Constant two.
         */
    static const BigBinaryInteger TWO;
        /**
         * Constant three.
         */
    static const BigBinaryInteger THREE;
        /**
         * Constant four.
         */
    static const BigBinaryInteger FOUR;
        /**
         * Constant five.
         */
    static const BigBinaryInteger FIVE;
    
    sint Compare(const BigBinaryInteger& a) const;
        

    protected:
        /**
         * Converts a string into base of 2^uint-type numbers by the algorithm that you provided me in the beginning of this project.
         *
         * @param v The input string
         */
    void AssignVal(const std::string& v);
        /**
         * Sets the MSB to the correct value.  Intended as a kind of pre-computation.
         */
    void SetMSB();

    void SetMSB(usint guessIdxChar);

	private:
		uint_type *m_value;
		usshort m_MSB;
		static const uschar m_uintBitLength;
		static const uint_type m_uintMax;
		static const uschar m_logUintBitLength;
		static const usint m_nSize;
		static uint_type ceilIntByUInt(const uint_type Number);
		static const BigBinaryInteger *m_modChain;
		static uint64_t GetMSB32(uint64_t x); //gets MSB for an unsigned integer
		static usint GetMSBUint_type(uint_type x);
		typedef typename doubleDataType<uint_type>::T Duint_type;
		enum State{
			INITIALIZED,GARBAGE
		};
		static usint GetMSBDUint_type(Duint_type x);
		
		State m_state;
        BigBinaryInteger MulIntegerByChar(uint_type b) const;


		static uint_type UintInBinaryToDecimal(uschar *a);
		static void double_bitVal(uschar *a);
		static void add_bitVal(uschar* a,uschar b);
	};


}//namespace ends

#endif