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

	template <usint N>
	struct log2{
		const static usint value = 1 + log2<N/2>::value;
	};

	template<>
	struct log2<2>{
		const static usint value = 1;
	};
	
	template <typename U>
	struct logdtype{
		const static usint value = log2<8*sizeof(U)>::value;
	};

	
	template<typename dtype>
	struct datatypechecker{
		// const static bool value = false ;
		//NP-TODO - This boolean check does not work in Linux. 
		const static bool value = true ;
		static_assert(value,"Data type provided is not supported in BigBinaryInteger");
	};

	template<>
	struct datatypechecker<uint8_t>{
		const static bool value = true ;	
	};

	template<>
	struct datatypechecker<uint16_t>{
		const static bool value = true ;	
	};

	template<>
	struct datatypechecker<uint32_t>{
		const static bool value = true ;	
	};

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
	
	template<typename utype>
	struct doubleDataType{
		typedef void T;
	};

	template<>
	struct doubleDataType<uint8_t>{
		typedef uint16_t T;
	};

	template<>
	struct doubleDataType<uint16_t>{
		typedef uint32_t T;
	};

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

		BigBinaryInteger  operator<<(usshort shift) const;

		BigBinaryInteger&  operator<<=(usshort shift);

		BigBinaryInteger  operator>>(usshort shift) const;

		BigBinaryInteger&  operator>>=(usshort shift);

        void PrintValueInDec() const;

        void SetValue(const std::string& str);

        void SetValue(const BigBinaryInteger& a);

        usshort GetMSB()const;

		usshort GetMSBCharNum()const;

        usint ConvertToInt() const;

		BigBinaryInteger Plus(const BigBinaryInteger& b) const;

		const BigBinaryInteger& operator+=(const BigBinaryInteger &b);

		const BigBinaryInteger& operator-=(const BigBinaryInteger &b);

		BigBinaryInteger Minus(const BigBinaryInteger& b) const;

		BigBinaryInteger Times(const BigBinaryInteger& b) const;

		BigBinaryInteger DividedBy(const BigBinaryInteger& b) const;

		BigBinaryInteger Mod(const BigBinaryInteger& modulus) const;

		BigBinaryInteger ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger& mu) const;

		BigBinaryInteger ModBarrett(const BigBinaryInteger& modulus, const BigBinaryInteger mu_arr[BARRETT_LEVELS+1]) const;

		BigBinaryInteger ModInverse(const BigBinaryInteger& modulus) const;

		BigBinaryInteger ModAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

		BigBinaryInteger ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const;

		BigBinaryInteger ModBarrettAdd(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

		BigBinaryInteger ModSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

		BigBinaryInteger ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

		BigBinaryInteger ModBarrettSub(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const;

		BigBinaryInteger ModMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

		BigBinaryInteger ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger& mu) const;

		BigBinaryInteger ModBarrettMul(const BigBinaryInteger& b, const BigBinaryInteger& modulus,const BigBinaryInteger mu_arr[BARRETT_LEVELS]) const;

		BigBinaryInteger ModExp(const BigBinaryInteger& b, const BigBinaryInteger& modulus) const;

		const std::string ToString() const;

		//template<typename uint_type,usint BITLENGTH>
		//friend bool CheckPowerofTwos(const BigBinaryInteger<uint_type,BITLENGTH>& m_numToCheck);

		bool CheckPowerofTwos(const BigBinaryInteger& m_numToCheck);

		usint GetLengthForBase(usint base) const {return GetMSB();}

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

		bool operator==(const BigBinaryInteger& a) const;

		bool operator!=(const BigBinaryInteger& a) const;

		bool operator> (const BigBinaryInteger& a) const;

		bool operator>=(const BigBinaryInteger& a) const;

		bool operator< (const BigBinaryInteger& a) const;

		bool operator<=(const BigBinaryInteger& a) const;

		//primitive operators
		inline BigBinaryInteger operator+(const BigBinaryInteger &a) const {return this->Plus(a);}

		inline BigBinaryInteger operator-(const BigBinaryInteger &a) const {return this->Minus(a);}

		inline BigBinaryInteger operator*(const BigBinaryInteger &a) const {return this->Times(a);}

		inline BigBinaryInteger operator%(const BigBinaryInteger &a) const {return this->Mod(a);}

		template<typename uint_type_c,usint BITLENGTH_c>
		friend std::ostream& operator<<(std::ostream& os, const BigBinaryInteger<uint_type_c,BITLENGTH_c> &ptr_obj);

		uschar GetBitAtIndex(usint index) const;

		BigBinaryInteger MulIntegerByChar(uint_type b) const;

		static const BigBinaryInteger ZERO;
		static const BigBinaryInteger ONE;
		static const BigBinaryInteger TWO;
		static const BigBinaryInteger THREE;
		static const BigBinaryInteger FOUR;
		static const BigBinaryInteger FIVE;

	protected: 

		void AssignVal(const std::string& v);

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
		
		sint Compare(const BigBinaryInteger& a) const;
		State m_state;


		static uint_type UintInBinaryToDecimal(uschar *a);
		static void double_bitVal(uschar *a);
		static void add_bitVal(uschar* a,uschar b);
	};


}//namespace ends

#endif
