/**
* @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 * Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu
 * <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 * 
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met: 1. Redistributions of source code must retain the above
 * copyright notice, this list of conditions and the following
 * disclaimer.  2. Redistributions in binary form must reproduce the
 * above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This file contains the main class for modulo unsigned big integers:
 * mubint. these are Big integers with an implied modulus.
  */

#ifndef LBCRYPTO_MATH_EXPINT32_MUBINT_H
#define LBCRYPTO_MATH_EXPINT32_MUBINT_H

#include <iostream>
#include <string>
#include <vector>
#include <type_traits>
#include <typeinfo>
#include <limits>
#include <fstream>
#include <stdexcept>
#include <functional>
#include <memory>
#include "../../utils/inttypes.h"
#include "../../utils/memory.h"

#indlude "ubint.h"
/**
 *@namespace exp_int32
 * The namespace of this code
 */
namespace exp_int32{

  /**
   * @brief Main class for big integers represented as an array of native (primitive) unsigned integers
   * @tparam limb_t native unsigned integer type
   */
  template<typename limb_t>
    class mubint: ubint<limb_t>
  {
      
  public:
      
    /**
     * Default constructor.
     */
    mubint();

    /**
     * Basic constructor for specifying the mubint.
     *
     * @param str is the initial integer represented as a string.
     */
    explicit mubint(const std::string& str);

    /**
     * Basic constructor for initializing big integer from an unsigned integer.
     *
     * @param init is the initial unsigned integer.
     */
    explicit mubint(usint init);

    /**
     * Basic constructor for copying a mubint
     *
     * @param rhs is the mubint to be copied.
     */
    explicit mubint(const mubint& rhs);

    /**
     * Basic constructor for move copying a mubint
     *
     * @param &&rhs is the mubint to be moved from.
     */
    mubint(mubint&& rhs);
    
    /**
     * Destructor.
     */
    ~mubint();
        
    /**
     * Assignment operator (move copy)
     *
     * @param &rhs is the mubint to be assigned from.
     * @return assigned mubint ref.
     */
    const mubint&  operator=(const mubint &rhs);

    /**
     * Assignment operator from unsigned integer
     *
     * @param val is the unsigned integer value that is assigned.
     * @return the assigned mubint ref.
     */
    inline const mubint& operator=(usint val) {
    //  *this = intTobint(val);
    	  *this = mubint(val);
      return *this;
    }

    /**
     * Move copy constructor
     *
     * @param &&rhs is the mubint to move.
     * @return object of type mubint.
     */
    const mubint&  operator=(mubint &&rhs);

    //Shift Operators
   
    /**
     * Left shift operator of mubint
     * @param shift is the amount to shift of type usint.
     * @return the object of type mubint
     */
    mubint  operator<<(usint shift) const;

    /**
     * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
     *
     * @param shift is the amount to shift of type usint.
     * @return the object of type mubint
     */
    const mubint&  operator<<=(usint shift);
        
    /**
     * Right shift operator of mubint
     * @param shift is the amount to shift of type usint.
     * @return the object of type mubint
     */
    mubint  operator>>(usint shift) const;

    /**
     * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
     *
     * @param shift is the amount to shift of type usint.
     * @return the object of type mubint
     */
    mubint&  operator>>=(usint shift);

    //Auxillary Functions

    /**
     * Prints the value of the vector of limbs to console in decimal format
     */
    void PrintLimbsInDec() const;

   /**
    * Prints the value of the vector of limbs to console in hex format
    */
    void PrintLimbsInHex() const;

    /**
     * Basic set method for setting the value of a mubint
     *
     * @param str is the string representation of the mubint to be copied.
     */
    void SetValue(const std::string& str);
        
    /**
     * Basic set method for setting the value of a mubint
     *
     * @param a is the mubint representation of the mubint to be assigned.
     */
    void SetValue(const mubint& a);

        
    /**
     * Returns the MSB location of the value.
     *
     * @return the index of the most significant bit.
     */
    usint GetMSB()const;

    /**
     * Returns the index number of the array in which MSB is located.
     *
     * @return the index of array of the most significant bit as usint.
     */
    usint GetMSBCharNum()const;

    /**
     * Converts the value to a usint.
     * if the mubint is larger than the max value representable
     * it is truncated to the least significant bits that fit
     * @return the int representation of the value as usint.
     */
    usint ConvertToUsint() const;
    
    /**
     * Converts the value to a usint. Soon to be DEPRECATED, because Int is not usint
     * if the mubint is larger than the max value representable
     * it is truncated to the least significant bits that fit
     * @return the int representation of the value as usint.
     */
    usint ConvertToInt() const;

    /**
     * Converts the value to a uint32_t.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * @return the int representation of the value as uint32_t
     */
    uint32_t ConvertToUint32() const;
    
    /**
     * Converts the value to a uint64_t.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     * @return the int representation of the value as uint64_t
     */
    uint64_t ConvertToUint64() const;

    /**
     * Converts the value to a float
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return float representation of the value.
     */
    float ConvertToFloat() const;

    /**
     * Converts the value to an double.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return double representation of the value.
     */
    double ConvertToDouble() const;


    /**
     * Converts the value to an long double.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return long double representation of the value.
     */
    long double ConvertToLongDouble() const;

    /**
     * Convert a value from an unsigned int to a mubint.
     *
     * @param m the value to convert from.
     * @return int represented as a mubint.
     */
    static mubint intTobint(usint m);

    //Arithemetic Operations

    /**
     * Addition operation.
     *
     * @param b is the value to add of type mubint.
     * @return result of the addition operation of type mubint.
     */
    mubint Add(const mubint& b) const;

		
    /**
     * Addition accumulator.
     *
     * @param &b is the value to add of type mubint.
     * @return result of the addition operation of type mubint.
     */
    const mubint& operator+=(const mubint &b);

		
    /**
     * Subtraction accumulator.
     *
     * @param &b is the value to subtract of type mubint.
     * @return result of the subtraction operation of type mubint.
     */
    const mubint& operator-=(const mubint &b);

    /**
     * Subtraction operation.
     *
     * @param b is the value to subtract of type mubint.
     * @return result of the subtraction operation of type mubint.
     */
    mubint Sub(const mubint& b) const;

        
    /**
     * Multiplication operation.
     *
     * @param b of type mubint is the value to multiply with.
     * @return result of the multiplication operation.
     */
    mubint Mul(const mubint& b) const;

    int divmnu_vect(mubint& q, mubint& r, const mubint& u, const mubint& v) const;

    /**
     * Division operation.
     *
     * @param b of type mubint is the value to divide by.
     * @return result of the division operation.
     */
    mubint DividedBy(const mubint& b) const;

    //modular arithmetic operations
		
    /**
     * returns the modulus with respect to the input value. Classical modular reduction algorithm is used.
     *
     * @param modulus is value of the modulus to perform. Its of type mubint.
     * @return mubint that is the result of the modulus operation.
     */
    mubint Mod(const mubint& modulus) const;
    
    /**
     * returns the modulus with respect to the input value.
     * Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
     * See the cpp file for details of the implementation. 
     *
     * @param modulus is the modulus to perform.
     * @param mu is the Barrett value.
     * @return is the result of the modulus operation.
     */
    mubint ModBarrett(const mubint& modulus, const mubint& mu) const;

    /**
     * returns the modulus with respect to the input value.
     * Implements generalized Barrett modular reduction algorithm. Uses an array of precomputed values \mu.
     * See the cpp file for details of the implementation. 
     *
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return result of the modulus operation.
     */
    //mubint ModBarrett(const mubint& modulus, const mubint mu_arr[BARRETT_LEVELS+1]) const;

    /**
     * returns the modulus inverse with respect to the input value.
     *
     * @param modulus is the modulus to perform.
     * @return result of the modulus inverse operation.
     */
    mubint ModInverse(const mubint& modulus) const;

    /**
     * Scalar modular addition.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus addition operation.
     */
    mubint ModAdd(const mubint& b, const mubint& modulus) const;

    /**
     * Modular addition where Barrett modulo reduction is used.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus addition operation.
     */
    //mubint ModBarrettAdd(const mubint& b, const mubint& modulus,const mubint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Modular addition where Barrett modulo reduction is used.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is one precomputed Barrett value.
     * @return is the result of the modulus addition operation.
     */
    mubint ModBarrettAdd(const mubint& b, const mubint& modulus,const mubint& mu) const;

    /**
     * Scalar modular subtraction.
     *
     * @param &b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus subtraction operation.
     */
    mubint ModSub(const mubint& b, const mubint& modulus) const;

    /**
     * Scalar modular subtraction where Barrett modular reduction is used.
     *
     * @param &b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    mubint ModBarrettSub(const mubint& b, const mubint& modulus,const mubint& mu) const;

    /**
     * Scalar modular subtraction where Barrett modular reduction is used.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus subtraction operation.
     */
    //mubint ModBarrettSub(const mubint& b, const mubint& modulus,const mubint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Scalar modulus multiplication.
     *
     * @param &b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    mubint ModMul(const mubint& b, const mubint& modulus) const;

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
    mubint ModBarrettMul(const mubint& b, const mubint& modulus,const mubint& mu) const;

    /**
     * Scalar modular multiplication where Barrett modular reduction is used.
     *
     * @param &b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus multiplication operation.
     */
    //mubint ModBarrettMul(const mubint& b, const mubint& modulus,const mubint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Scalar modular exponentiation. Square-and-multiply algorithm is used.
     *
     * @param &b is the scalar to exponentiate.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    mubint ModExp(const mubint& b, const mubint& modulus) const;

    /**
     * Stores the based 10 equivalent/Decimal value of the mubint in a string object and returns it.
     *
     * @return value of this mubint in base 10 represented as a string.
     */
    const std::string ToString() const;		

    /**
     * Tests whether the mubint is a power of 2.
     *
     * @param m_numToCheck is the value to check.
     * @return true if the input is a power of 2, false otherwise.
     */
    bool CheckIfPowerOfTwo(const mubint& m_numToCheck);

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
    usint GetDigitAtIndexForBase(usint index, usint base) const;

    /**
     * Convert a string representation of a binary number to a mubint.
     *
     * @param bitString the binary num in string.
     * @return the  number represented as a mubint.
     */
    static mubint BinaryStringToMubint(const std::string& bitString);

    /**
     * Exponentiation of a bigInteger x. Returns x^p
     *
     * @param p the exponent.
     * @return the mubint x^p.
     */
    mubint Exp(usint p) const;

    /**
     * Test equality of the inputs.
     *
     * @param a second value to test.
     * @return true if the inputs are equal.
     */
    bool operator==(const mubint& a) const;

    /**
     * Test inequality of the inputs.
     *
     * @param a second value to test.
     * @return true if the inputs are inequal.
     */
    bool operator!=(const mubint& a) const;

    /**
     * Test if first input is great than the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is greater.
     */
    bool operator> (const mubint& a) const;

    /**
     * Test if first input is great than or equal to the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is greater than or equal to the second input.
     */
    bool operator>=(const mubint& a) const;

    /**
     * Test if first input is less than the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is lesser.
     */
    bool operator< (const mubint& a) const;

    /**
     * Test if first input is less than or equal to the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is less than or equal to the second input.
     */
    bool operator<=(const mubint& a) const;

    //overloaded binary operators based on integer arithmetic and comparison functions
    /**
     * Addition operation.
     *
     * @param a is the value to add.
     * @return is the result of the addition operation.
     */
    inline mubint operator+(const mubint &a) const {return this->Add(a);}

    /**
     * Subtraction operation.
     *
     * @param a is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    inline mubint operator-(const mubint &a) const {return this->Sub(a);}

    /**
     * Multiplication operation.
     *
     * @param a is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    inline mubint operator*(const mubint &a) const {return this->Mul(a);}

    /**
     * Modulo operation. Classical modular reduction algorithm is used.
     *
     * @param a is the value to Mod.
     * @return is the result of the modulus operation.
     */
    inline mubint operator%(const mubint &a) const {return this->Mod(a);}

    /**
     * Division operation.
     *
     * @param a is the value to divide.
     * @param b is the value to divide by.
     * @return is the result of the integral part after division operation.
     */
    inline mubint operator/ (const mubint &a) const {return this->DividedBy(a);}

    /**
     * Console output operation.
     *
     * @param os is the std ostream object.
     * @param ptr_obj is mubint to be printed.
     * @return is the ostream object.
     */
    template<typename limb_t_c>
    friend std::ostream& operator<<(std::ostream& os, const mubint<limb_t_c> &ptr_obj);
    
    /**
     * Gets the bit at the specified index.
     *
     * @param index is the index of the bit to get.
     * @return resulting bit.
     */
    uschar GetBitAtIndex(usint index) const;


    /**
     * Sets the int value at the specified index.
     *
     * @param index is the index of the int to set in the uint array.
     */
    void SetIntAtIndex(usint idx, limb_t value);
        
    //constant definations
        
    /**
     * Constant zero.
     */
    static const mubint ZERO;

    /**
     * Constant one.
     */
    static const mubint ONE;

    /**
     * Constant two.
     */
    static const mubint TWO;

    /**
     * Constant three.
     */
    static const mubint THREE;

    /**
     * Constant four.
     */
    static const mubint FOUR;

    /**
     * Constant five.
     */
    static const mubint FIVE;
    
    /**
     * Compares the current mubint to mubint a.
     *
     * @param a is the mubint to be compared with.
     * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
     */
    sint Compare(const mubint& a) const;

    /**
     *  Set this int to 1.
     */
    inline void SetIdentity() { *this = mubint::ONE; };

    /**
     * A zero allocator that is called by the Matrix class. It is used to initialize a Matrix of mubint objects.
     */
    static std::function<unique_ptr<mubint>()> Allocator;

  protected:
    
    /**
     * Converts the string v into base-r integer where r is equal to 2^bitwidth of limb data type.
     *
     * @param v The input string
     */
    void AssignVal(const std::string& v);

    /**
     * Sets the MSB to the correct value from the mubint.
     */
    void SetMSB();

    /**
     * Sets the MSB to the correct value from the mubint.
     * @param guessIdxChar is the hint of the MSB position.
     */
    void SetMSB(usint guessIdxChar);

    //  private:
  public: //todo for debug onlhy

    //pointer to the array storing the native integers.
    //vector<limb_t> m_value {(limb_t)0};
    vector<limb_t> m_value;

    //variable that stores the MOST SIGNIFICANT BIT position in the number. Note MSB(1) = 1 NOT 0
    usint m_MSB;

    //variable to store the bitlength of the limb data type.
    static const usint m_limbBitLength;

    //variable to store the maximum value of the limb data type.
    static const usint m_MaxLimb;

    //variable to store the log(base 2) of the number of bits in the limb data type.
    static const usint m_log2LimbBitLength;

    //variable to store the size of the data array.
    static const usint m_nSize;

    //The maximum number of digits in biginteger. It is used by the cout(ostream) function for printing the bignumber.
    static const usint m_numDigitInPrintval=1500;
    /**
     * function to return the ceiling of the number divided by the number of bits in the limb data type.
     * @param Number is the number to be divided.
     * @return the ceiling of Number/(bits in the limb data type)
     */
    static usint ceilIntByUInt(const limb_t Number);

    //currently unused array
    static const mubint *m_modChain;
		
    /**
     * function to return the MSB of a 32 bit number.
     * @param x is the 32 bit integer.
     * @return the MSB position in the 32 bit number x. Note MSB(1) is 1 NOT zero!!!!!
     */


  public: 
		
    static uint64_t GetMSB32(uint64_t x);
    /**
     * function to return the MSB of number.
     * @param x is the number.
     * @return the MSB position in the number x.Note MSB(1) is 1 NOT zero!!!!!
     */
		
    static usint GetMSBlimb_t(limb_t x);
		
		
  static uint64_t GetMSB64(uint64_t x);
    /**
     * function to return the MSB of 64 bit number.
     * @param x is the number.
     * @return the MSB position in the number x. Note MSB(1) is 1 NOT zero!!!!!
     */

  //  private:
  public:  //todo: changed only for debug
    //Dlimb_t is the data type that has twice as many bits in the limb data type.
    typedef typename DoubleDataType<limb_t>::T Dlimb_t;

    //enum defination to represent the state of the mubint.
    enum State{
      INITIALIZED,GARBAGE
    };

    /**
     * function to return the MSB of number that is of type Dlimb_t.
     * @param x is the number.
     * @return the MSB position in the number x. Note MSB(1) is 1 NOT zero!!!!!
     */
    static usint GetMSBDlimb_t(Dlimb_t x);

    //enum to store the state of the 
    State m_state;


    /**
     * function that returns the mubint after multiplication by b.
     * @param b is the number to be multiplied.
     * @return the mubint after the multiplication.
     */
    mubint MulIntegerByLimb(limb_t b) const;
		
    /**
     * function that returns the decimal value from the binary array a.
     * @param a is a pointer to the binary array.
     * @return the decimal value.
     */
    static limb_t UintInBinaryToDecimal(uschar *a);

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

  ///**
  // * Division operation.
  // *
  // * @param a is the value to divide.
  // * @param b is the value to divide by.
  // * @return is the result of the division operation.
  // */
  template<typename limb_t>
  inline mubint<limb_t> operator/(const mubint<limb_t> &a, const mubint<limb_t> &b) {return a.DividedBy(b);}

}//namespace ends

#endif //LBCRYPTO_MATH_EXPINT32_MUBINT_H

