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
 * This file contains the main class for big integers: bint. Big
 * integers are represented as arrays of native usigned integers. The
 * native integer type is supplied as a template parameter.  Currently
 * implementations based on uint8_t, uint16_t, and uint32_t are
 * supported. The second template parameter is the maximum bitwidth
 * for the big integer.
 */

#ifndef LBCRYPTO_MATH_EXPINT32_BINT_H
#define LBCRYPTO_MATH_EXPINT32_BINT_H

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

/**
 *@namespace exp_int32
 * The namespace of this code
 */
namespace exp_int32{

  /**The following structs are needed for initialization of bint at
   *the preprocessing stage.  The structs compute certain values using
   *template metaprogramming approach and mostly follow recursion to
   *calculate value(s).
   */

  /**
   * @brief  Struct to find log value of N.
   *Needed in the preprocessing step of bint to determine bitwidth.
   *
   * @tparam N bitwidth.
   */

  template <usint N>
  struct Log2{
    const static usint value = 1 + Log2<N/2>::value;
  };
    
  /**
   * @brief Struct to find log 2 value of N.
   *Base case for recursion.
   *Needed in the preprocessing step of bint to determine bitwidth.
   */
  template<>
  struct Log2<2>{
    const static usint value = 1;
  };
    
  /**
   * @brief Struct to find log value of U where U is a primitive datatype.
   *Needed in the preprocessing step of bint to determine bitwidth.
   *
   * @tparam U primitive data type.
   */
#if 0 //todo delete
  template <typename U>
  struct LogDtype{
    const static usint value = Log2<8*sizeof(U)>::value;
  };
#endif
  /**
   * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t}
   *
   * @tparam Dtype primitive datatype.
   */
  template<typename Dtype>
  struct DataTypeChecker{
    const static bool value = false ;
  };

  /**
   * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t}.
   * sets value true if datatype is unsigned integer 8 bit.
   */
  template<>
  struct DataTypeChecker<uint8_t>{
    const static bool value = true ;
  };

  /**
   * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t}.
   * sets value true if datatype is unsigned integer 16 bit.
   */
  template<>
  struct DataTypeChecker<uint16_t>{
    const static bool value = true ;	
  };

  /**
   * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t}.
   * sets value true if datatype is unsigned integer 32 bit.
   */
  template<>
  struct DataTypeChecker<uint32_t>{
    const static bool value = true ;	
  };

  /**
   * @brief Struct for validating if Dtype is amongst {uint8_t, uint16_t, uint32_t, uint64_t}.
   * sets value true if datatype is unsigned integer 64 bit.
   */
  template<>
  struct DataTypeChecker<uint64_t>{
    const static bool value = true ;	
  };

#if 0
  /**
   * @brief Struct for calculating bit width from data type. 
   * Sets value to the bitwidth of uint_type
   *
   * @tparam uint_type native integer data type.
   */
  template <typename uint_type>
  struct UIntBitWidth{
    const static int value = 8*sizeof(uint_type);
  };
#endif
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
   * Sets T as of type unsigned integer 16 bit if limb datatype is 8bit
   */
  template<>
  struct DoubleDataType<uint8_t>{
    typedef uint16_t T;
  };

  /**
   * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
   * sets T as of type unsigned integer 32 bit if limb datatype is 16bit
   */
  template<>
  struct DoubleDataType<uint16_t>{
    typedef uint32_t T;
  };

  /**
   * @brief Struct to determine a datatype that is twice as big(bitwise) as utype.
   * sets T as of type unsigned integer 64 bit if limb datatype is 32bit
   */
  template<>
  struct DoubleDataType<uint32_t>{
    typedef uint64_t T;
  };


  const double LOG2_10 = 3.32192809;	//!< @brief A pre-computed constant of Log base 2 of 10.
  //todo delete
  //const usint BARRETT_LEVELS = 8;		//!< @brief The number of levels (precomputed values) used in the Barrett reductions.

  /**
   * @brief Main class for big integers represented as an array of native (primitive) unsigned integers
   * @tparam limb_t native unsigned integer type
   * @tparam BITLENGTH maximum bitdwidth supported for big integers
   */
  template<typename limb_t,usint BITLENGTH>
  class bint
  {
      
  public:
      
    /**
     * Default constructor.
     */
    bint();

    /**
     * Basic constructor for specifying the integer.
     *
     * @param str is the initial integer represented as a string.
     */
    explicit bint(const std::string& str);

    /**
     * Basic constructor for initializing big integer from an unsigned integer.
     *
     * @param init is the initial integer.
     */
    explicit bint(usint init);

    /**
     * Basic constructor for copying a big integer
     *
     * @param bigInteger is the big integer to be copied.
     */
    explicit bint(const bint& bigInteger);

    /**
     * Basic constructor for move copying a big  integer
     *
     * @param &&bigInteger is the big  integer to be moved from.
     */
    bint(bint &&bigInteger);
    
    /**
     * Destructor.
     */
    ~bint();
        
    /**
     * Assignment operator
     *
     * @param &rhs is the big integer to be assigned from.
     * @return assigned bint ref.
     */
    const bint&  operator=(const bint &rhs);

    /**
     * Assignment operator from unsigned integer
     *
     * @param val is the unsigned integer value that is assigned.
     * @return the assigned Big  Integer ref.
     */
    inline const bint& operator=(usint val) {
    //  *this = intTobint(val);
    	  *this = bint(val);
      return *this;
    }

    /**
     * Move copy constructor
     *
     * @param &&rhs is the big  integer to move.
     * @return object of type bint.
     */
    const bint&  operator=(bint &&rhs);

    //Shift Operators
   
    /**
     * Left shift operator of big  integer
     * @param shift is the amount to shift of type usshort.
     * @return the object of type bint
     */
    bint  operator<<(usshort shift) const;

    /**
     * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
     *
     * @param shift is the amount to shift of type usshort.
     * @return the object of type bint
     */
    const bint&  operator<<=(usshort shift);
        
    /**
     * Right shift operator of big  integer
     * @param shift is the amount to shift of type usshort.
     * @return the object of type bint
     */
    bint  operator>>(usshort shift) const;

    /**
     * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
     *
     * @param shift is the amount to shift of type usshort.
     * @return the object of type bint
     */
    bint&  operator>>=(usshort shift);

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
     * Basic set method for setting the value of a big  integer
     *
     * @param str is the string representation of the big  integer to be copied.
     */
    void SetValue(const std::string& str);
        
    /**
     * Basic set method for setting the value of a big  integer
     *
     * @param a is the big  integer representation of the big  integer to be assigned.
     */
    void SetValue(const bint& a);

        
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
     * Converts the value to a usint.
     * if the bint is larger than the max value representable
     * it is truncated to the least significant bits that fit
     * @return the int representation of the value as usint.
     */
    usint ConvertToUsint() const;
    
    /**
     * Converts the value to a uint32_t.
     * if the bint is larger than the max value representable
     * std::out_of_range is thrown
     * @return the int representation of the value as uint32_t
     */
    uint32_t ConvertToUint32() const;
    
    /**
     * Converts the value to a uint64_t.
     * if the bint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     * @return the int representation of the value as uint64_t
     */
    uint64_t ConvertToUint64() const;

    /**
     * Converts the value to a float
     * if the bint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return float representation of the value.
     */
    float ConvertToFloat() const;

    /**
     * Converts the value to an double.
     * if the bint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return double representation of the value.
     */
    double ConvertToDouble() const;


    /**
     * Converts the value to an long double.
     * if the bint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return long double representation of the value.
     */
    long double ConvertToLongDouble() const;

    /**
     * Convert a value from an int to a Big Int.
     *
     * @param m the value to convert from.
     * @return int represented as a big  int.
     */
    static bint intTobint(usint m);

    //Arithemetic Operations

    /**
     * Addition operation.
     *
     * @param b is the value to add of type Big  Integer.
     * @return result of the addition operation of type Big Integer.
     */
    bint Add(const bint& b) const;

		
    /**
     * Addition accumulator.
     *
     * @param &b is the value to add of type Big  Integer.
     * @return result of the addition operation of type Big  Integer.
     */
    const bint& operator+=(const bint &b);

		
    /**
     * Subtraction accumulator.
     *
     * @param &b is the value to subtract of type Big  Integer.
     * @return result of the subtraction operation of type Big  Integer.
     */
    const bint& operator-=(const bint &b);

    /**
     * Subtraction operation.
     *
     * @param b is the value to subtract of type Big  Integer.
     * @return result of the subtraction operation of type Big  Integer.
     */
    bint Sub(const bint& b) const;

        
    /**
     * Multiplication operation.
     *
     * @param b of type Big  Integer is the value to multiply with.
     * @return result of the multiplication operation.
     */
    bint Mul(const bint& b) const;

    int divmnu_vect(vector<limb_t>& q, vector<limb_t>& r, const vector<limb_t>& u, const vector<limb_t>& v);

    /**
     * Division operation.
     *
     * @param b of type bint is the value to divide by.
     * @return result of the division operation.
     */
    bint DividedBy(const bint& b) const;

    //modular arithmetic operations
		
    /**
     * returns the modulus with respect to the input value. Classical modular reduction algorithm is used.
     *
     * @param modulus is value of the modulus to perform. Its of type bint.
     * @return bint that is the result of the modulus operation.
     */
    bint Mod(const bint& modulus) const;
    
    /**
     * returns the modulus with respect to the input value.
     * Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
     * See the cpp file for details of the implementation. 
     *
     * @param modulus is the modulus to perform.
     * @param mu is the Barrett value.
     * @return is the result of the modulus operation.
     */
    bint ModBarrett(const bint& modulus, const bint& mu) const;

    /**
     * returns the modulus with respect to the input value.
     * Implements generalized Barrett modular reduction algorithm. Uses an array of precomputed values \mu.
     * See the cpp file for details of the implementation. 
     *
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return result of the modulus operation.
     */
    //bint ModBarrett(const bint& modulus, const bint mu_arr[BARRETT_LEVELS+1]) const;

    /**
     * returns the modulus inverse with respect to the input value.
     *
     * @param modulus is the modulus to perform.
     * @return result of the modulus inverse operation.
     */
    bint ModInverse(const bint& modulus) const;

    /**
     * Scalar modular addition.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus addition operation.
     */
    bint ModAdd(const bint& b, const bint& modulus) const;

    /**
     * Modular addition where Barrett modulo reduction is used.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus addition operation.
     */
    //bint ModBarrettAdd(const bint& b, const bint& modulus,const bint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Modular addition where Barrett modulo reduction is used.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is one precomputed Barrett value.
     * @return is the result of the modulus addition operation.
     */
    bint ModBarrettAdd(const bint& b, const bint& modulus,const bint& mu) const;

    /**
     * Scalar modular subtraction.
     *
     * @param &b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus subtraction operation.
     */
    bint ModSub(const bint& b, const bint& modulus) const;

    /**
     * Scalar modular subtraction where Barrett modular reduction is used.
     *
     * @param &b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    bint ModBarrettSub(const bint& b, const bint& modulus,const bint& mu) const;

    /**
     * Scalar modular subtraction where Barrett modular reduction is used.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus subtraction operation.
     */
    //bint ModBarrettSub(const bint& b, const bint& modulus,const bint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Scalar modulus multiplication.
     *
     * @param &b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    bint ModMul(const bint& b, const bint& modulus) const;

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
    bint ModBarrettMul(const bint& b, const bint& modulus,const bint& mu) const;

    /**
     * Scalar modular multiplication where Barrett modular reduction is used.
     *
     * @param &b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus multiplication operation.
     */
    //bint ModBarrettMul(const bint& b, const bint& modulus,const bint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Scalar modular exponentiation. Square-and-multiply algorithm is used.
     *
     * @param &b is the scalar to exponentiate.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    bint ModExp(const bint& b, const bint& modulus) const;

    /**
     * Stores the based 10 equivalent/Decimal value of the bint in a string object and returns it.
     *
     * @return value of this bint in base 10 represented as a string.
     */
    const std::string ToString() const;		

    /**
     * Tests whether the bint is a power of 2.
     *
     * @param m_numToCheck is the value to check.
     * @return true if the input is a power of 2, false otherwise.
     */
    bool CheckIfPowerOfTwo(const bint& m_numToCheck);

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
     * Convert a string representation of a binary number to a Big Int.
     *
     * @param bitString the binary num in string.
     * @return the  number represented as a big  int.
     */
    static bint BinaryStringToBint(const std::string& bitString);

    /**
     * Exponentiation of a bigInteger x. Returns x^p
     *
     * @param p the exponent.
     * @return the big  integer x^p.
     */
    bint Exp(usint p) const;

    /**
     * Test equality of the inputs.
     *
     * @param a second value to test.
     * @return true if the inputs are equal.
     */
    bool operator==(const bint& a) const;

    /**
     * Test inequality of the inputs.
     *
     * @param a second value to test.
     * @return true if the inputs are inequal.
     */
    bool operator!=(const bint& a) const;

    /**
     * Test if first input is great than the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is greater.
     */
    bool operator> (const bint& a) const;

    /**
     * Test if first input is great than or equal to the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is greater than or equal to the second input.
     */
    bool operator>=(const bint& a) const;

    /**
     * Test if first input is less than the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is lesser.
     */
    bool operator< (const bint& a) const;

    /**
     * Test if first input is less than or equal to the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is less than or equal to the second input.
     */
    bool operator<=(const bint& a) const;

    //overloaded binary operators based on integer arithmetic and comparison functions
    /**
     * Addition operation.
     *
     * @param a is the value to add.
     * @return is the result of the addition operation.
     */
    inline bint operator+(const bint &a) const {return this->Add(a);}

    /**
     * Subtraction operation.
     *
     * @param a is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    inline bint operator-(const bint &a) const {return this->Sub(a);}

    /**
     * Multiplication operation.
     *
     * @param a is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    inline bint operator*(const bint &a) const {return this->Mul(a);}

    /**
     * Modulo operation. Classical modular reduction algorithm is used.
     *
     * @param a is the value to Mod.
     * @return is the result of the modulus operation.
     */
    inline bint operator%(const bint &a) const {return this->Mod(a);}

    /**
     * Division operation.
     *
     * @param a is the value to divide.
     * @param b is the value to divide by.
     * @return is the result of the integral part after division operation.
     */
    inline bint operator/ (const bint &a) const {return this->DividedBy(a);}

    /**
     * Console output operation.
     *
     * @param os is the std ostream object.
     * @param ptr_obj is bint to be printed.
     * @return is the ostream object.
     */
    template<typename limb_t_c,usint BITLENGTH_c>
    friend std::ostream& operator<<(std::ostream& os, const bint<limb_t_c,BITLENGTH_c> &ptr_obj);
    
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
    static const bint ZERO;

    /**
     * Constant one.
     */
    static const bint ONE;

    /**
     * Constant two.
     */
    static const bint TWO;

    /**
     * Constant three.
     */
    static const bint THREE;

    /**
     * Constant four.
     */
    static const bint FOUR;

    /**
     * Constant five.
     */
    static const bint FIVE;
    
    /**
     * Compares the current bint to bint a.
     *
     * @param a is the bint to be compared with.
     * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
     */
    sint Compare(const bint& a) const;

    /**
     *  Set this int to 1.
     */
    inline void SetIdentity() { *this = bint::ONE; };

    /**
     * A zero allocator that is called by the Matrix class. It is used to initialize a Matrix of bint objects.
     */
    static std::function<unique_ptr<bint>()> Allocator;

  protected:
    
    /**
     * Converts the string v into base-r integer where r is equal to 2^bitwidth of limb data type.
     *
     * @param v The input string
     */
    void AssignVal(const std::string& v);

    /**
     * Sets the MSB to the correct value from the bint.
     */
    void SetMSB();

    /**
     * Sets the MSB to the correct value from the bint.
     * @param guessIdxChar is the hint of the MSB position.
     */
    void SetMSB(usint guessIdxChar);

    //  private:
  public: //todo for debug onlhy

    //pointer to the array storing the native integers.
    //vector<limb_t> m_value {(limb_t)0};
    vector<limb_t> m_value;

    //variable that stores the MOST SIGNIFICANT BIT position in the number. Note MSB(1) = 1 NOT 0
    usshort m_MSB;

    //variable to store the bitlength of the limb data type.
    static const usint m_limbBitLength;

    //variable to store the maximum value of the limb data type.
    static const usint m_MaxLimb;



    //variable to store the log(base 2) of the number of bits in the limb data type.
    static const usint m_log2LimbBitLength;

    //variable to store the size of the data array.
    static const usint m_nSize;

    //The maximum number of digits in biginteger. It is used by the cout(ostream) function for printing the bignumber.
    static const usint m_numDigitInPrintval;
    /**
     * function to return the ceiling of the number divided by the number of bits in the limb data type.
     * @param Number is the number to be divided.
     * @return the ceiling of Number/(bits in the limb data type)
     */
    static usint ceilIntByUInt(const limb_t Number);

    //currently unused array
    static const bint *m_modChain;
		
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

    //enum defination to represent the state of the big  integer.
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
     * function that returns the bint after multiplication by b.
     * @param b is the number to be multiplied.
     * @return the bint after the multiplication.
     */
    bint MulIntegerByLimb(limb_t b) const;
		
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
  //template<typename limb_t,usint BITLENGTH>
  //inline bint<limb_t,BITLENGTH> operator/(const bint<limb_t,BITLENGTH> &a, const bint<limb_t,BITLENGTH> &b) {return a.DividedBy(b);}

}//namespace ends

#endif //LBCRYPTO_MATH_EXPINT32_BINT_H

