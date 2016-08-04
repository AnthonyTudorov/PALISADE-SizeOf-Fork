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
 * This file contains the main class for unsigned big integers: ubint. Big
 * integers are represented as arrays of machine native unsigned integers. The
 * native integer type is supplied as a template parameter.  Currently
 * implementation based on uint32_t is
 * supported. a native double the base integer size is also needed.
  */

#ifndef LBCRYPTO_MATH_EXPINT32_UBINT_H
#define LBCRYPTO_MATH_EXPINT32_UBINT_H

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

  /**The following structs are needed for initialization of ubint at
   *the preprocessing stage.  The structs compute certain values using
   *template metaprogramming approach and mostly follow recursion to
   *calculate value(s).
   */

  /**
   * @brief  Struct to find log value of N.
   *Needed in the preprocessing step of ubint to determine bitwidth.
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
   *Needed in the preprocessing step of ubint to determine bitwidth.
   */
  template<>
  struct Log2<2>{
    const static usint value = 1;
  };

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

  //////////////////////////////////////////////////////////////////////////////////////////////////
  // Definition starts here
  //////////////////////////////////////////////////////////////////////////////////////////////////
  template<typename limb_t>
  class ubint
  {
      
  public:
      
    /**
     * Default constructor.
     */
    ubint();

    /**
     * Basic constructor for specifying the ubint.
     *
     * @param str is the initial integer represented as a string.
     */
    explicit ubint(const std::string& str);

    /**
     * Basic constructor for initializing big integer from an unsigned integer.
     *
     * @param init is the initial unsigned integer.
     */
    explicit ubint(usint init);

    /**
     * Basic constructor for initializing big integer from an signed integer.
     * because the compiler needs to know how to promote it in statements
     * like  ubint a(0);  it promotes 0 to int but then what?
     *
     * @param init is the initial signed integer.
     */
    explicit ubint(sint init);

    /**
     * Basic constructor for initializing big integer from a uint64_t.
     *
     * @param init is the initial 64 bit unsigned integer.
     */
    explicit ubint(uint64_t init);

    /**
     * Basic constructor for initializing big integer from an int64_t.
     *
     * @param init is the initial 64 bit signed integer.
     */
    explicit ubint(int64_t init);

    /**
     * Basic constructor for copying a ubint
     *
     * @param rhs is the ubint to be copied.
     */
    explicit ubint(const ubint& rhs);

    /**
     * Basic constructor for move copying a ubint
     *
     * @param &&rhs is the ubint to be moved from.
     */
    ubint(ubint&& rhs);
    
    /**
     * Destructor.
     */
    ~ubint();
        
    /**
     * Assignment operator (move copy)
     *
     * @param &rhs is the ubint to be assigned from.
     * @return assigned ubint ref.
     */
    const ubint&  operator=(const ubint &rhs);

    /**
     * Assignment operator from unsigned integer
     *
     * @param val is the unsigned integer value that is assigned.
     * @return the assigned ubint ref.
     */
    inline const ubint& operator=(usint val) {
    //  *this = intTobint(val);
    	  *this = ubint(val);
      return *this;
    }

    /**
     * Assignment operator from string
     *
     * @param val is the string value that is assigned.
     * @return the assigned ubint ref.
     */
    inline const ubint& operator=(std::string val) {
      *this = ubint(val);
      return *this;
    }


    /**
     * Move copy constructor
     *
     * @param &&rhs is the ubint to move.
     * @return object of type ubint.
     */
    const ubint&  operator=(ubint &&rhs);

    //Shift Operators
   
    /**
     * Left shift operator of ubint
     * @param shift is the amount to shift of type usint.
     * @return the object of type ubint
     */
    ubint  operator<<(usint shift) const;

    /**
     * Left shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
     *
     * @param shift is the amount to shift of type usint.
     * @return the object of type ubint
     */
    const ubint&  operator<<=(usint shift);
        
    /**
     * Right shift operator of ubint
     * @param shift is the amount to shift of type usint.
     * @return the object of type ubint
     */
    ubint  operator>>(usint shift) const;

    /**
     * Right shift operator uses in-place algorithm and operates on the same variable. It is used to reduce the copy constructor call.
     *
     * @param shift is the amount to shift of type usint.
     * @return the object of type ubint
     */
    ubint&  operator>>=(usint shift);

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
     * Basic set method for setting the value of a ubint
     *
     * @param str is the string representation of the ubint to be copied.
     */
    void SetValue(const std::string& str);
        
    /**
     * Basic set method for setting the value of a ubint
     *
     * @param a is the ubint representation of the ubint to be assigned.
     */
    void SetValue(const ubint& a);

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
     * deprecated
     */
    //  usint GetMSBCharNum()const;

    /**
     * Converts the value to a usint.
     * if the ubint is larger than the max value representable
     * it is truncated to the least significant bits that fit
     * @return the int representation of the value as usint.
     */
    usint ConvertToUsint() const;
    
    /**
     * Converts the value to a usint. Soon to be DEPRECATED, because Int is not usint
     * if the ubint is larger than the max value representable
     * it is truncated to the least significant bits that fit
     * @return the int representation of the value as usint.
     */
    usint ConvertToInt() const;

    /**
     * Converts the value to a uint32_t.
     * if the ubint is larger than the max value representable
     * std::out_of_range is thrown
     * @return the int representation of the value as uint32_t
     */
    uint32_t ConvertToUint32() const;
    
    /**
     * Converts the value to a uint64_t.
     * if the ubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     * @return the int representation of the value as uint64_t
     */
    uint64_t ConvertToUint64() const;

    /**
     * Converts the value to a float
     * if the ubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return float representation of the value.
     */
    float ConvertToFloat() const;

    /**
     * Converts the value to an double.
     * if the ubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return double representation of the value.
     */
    double ConvertToDouble() const;


    /**
     * Converts the value to an long double.
     * if the ubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return long double representation of the value.
     */
    long double ConvertToLongDouble() const;

    /**
     * Convert a value from an unsigned int to a ubint.
     *
     * @param m the value to convert from.
     * @return int represented as a ubint.
     */
    static ubint UsintToUbint(usint m);

    //Arithemetic Operations

    /**
     * Addition operation.
     *
     * @param b is the value to add of type ubint.
     * @return result of the addition operation of type ubint.
     */
    ubint Add(const ubint& b) const;

		
    /**
     * Addition accumulator.
     *
     * @param &b is the value to add of type ubint.
     * @return result of the addition operation of type ubint.
     */
    const ubint& operator+=(const ubint &b);

		
    /**
     * Subtraction accumulator.
     *
     * @param &b is the value to subtract of type ubint.
     * @return result of the subtraction operation of type ubint.
     */
    const ubint& operator-=(const ubint &b);

    /**
     * Multiplication accumulator.
     *
     * @param &b is the value to multiply by of type ubint.
     * @return result of the multiplication operation of type ubint.
     */
    const ubint& operator*=(const ubint &b);

    /**
     * Division accumulator.
     *
     * @param &b is the value to divide by of type ubint.
     * @return result of the division operation of type ubint.
     */
    const ubint& operator/=(const ubint &b);

    /**
     * Modulus accumulator.
     *
     * @param &b is the value to modulo by of type ubint.
     * @return result of the modulo operation of type ubint.
     */
    const ubint& operator%=(const ubint &b);

    /**
     * Subtraction operation.
     *
     * @param b is the value to subtract of type ubint.
     * @return result of the subtraction operation of type ubint.
     */
    ubint Sub(const ubint& b) const;

        
    /**
     * Multiplication operation.
     *
     * @param b of type ubint is the value to multiply with.
     * @return result of the multiplication operation.
     */
    ubint Mul(const ubint& b) const;

    /**
     * Division operation.
     *
     * @param b of type ubint is the value to divide by.
     * @return result of the division operation.
     *
     */
    ubint Div(const ubint& b) const;

    /**
     * Exponentiation of a bigInteger x. Returns x^p
     *
     * @param p the exponent.
     * @return the ubint x^p.
     */
    ubint Exp(usint p) const;
    
    //modular arithmetic operations
		
    /**
     * returns the modulus with respect to the input value. Classical modular reduction algorithm is used.
     *
     * @param modulus is value of the modulus to perform. Its of type ubint.
     * @return ubint that is the result of the modulus operation.
     */
    ubint Mod(const ubint& modulus) const;
    
    /**
     * returns the modulus with respect to the input value.
     * Implements generalized Barrett modular reduction algorithm. Uses one precomputed value of mu.
     * See the cpp file for details of the implementation. 
     *
     * @param modulus is the modulus to perform.
     * @param mu is the Barrett value.
     * @return is the result of the modulus operation.
     */
    ubint ModBarrett(const ubint& modulus, const ubint& mu) const;

    /**
     * returns the modulus with respect to the input value.
     * Implements generalized Barrett modular reduction algorithm. Uses an array of precomputed values \mu.
     * See the cpp file for details of the implementation. 
     *
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return result of the modulus operation.
     */
    //ubint ModBarrett(const ubint& modulus, const ubint mu_arr[BARRETT_LEVELS+1]) const;

    /**
     * returns the modulus inverse with respect to the input value.
     *
     * @param modulus is the modulus to perform.
     * @return result of the modulus inverse operation.
     */
    ubint ModInverse(const ubint& modulus) const;

    /**
     * Scalar modular addition.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus addition operation.
     */
    ubint ModAdd(const ubint& b, const ubint& modulus) const;

    /**
     * Modular addition where Barrett modulo reduction is used.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus addition operation.
     */
    //ubint ModBarrettAdd(const ubint& b, const ubint& modulus,const ubint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Modular addition where Barrett modulo reduction is used.
     *
     * @param &b is the scalar to add.
     * @param modulus is the modulus to perform operations with.
     * @param mu is one precomputed Barrett value.
     * @return is the result of the modulus addition operation.
     */
    ubint ModBarrettAdd(const ubint& b, const ubint& modulus,const ubint& mu) const;

    /**
     * Scalar modular subtraction.
     *
     * @param &b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @return result of the modulus subtraction operation.
     */
    ubint ModSub(const ubint& b, const ubint& modulus) const;

    /**
     * Scalar modular subtraction where Barrett modular reduction is used.
     *
     * @param &b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu is the Barrett value.
     * @return is the result of the modulus subtraction operation.
     */
    ubint ModBarrettSub(const ubint& b, const ubint& modulus,const ubint& mu) const;

    /**
     * Scalar modular subtraction where Barrett modular reduction is used.
     *
     * @param b is the scalar to subtract.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus subtraction operation.
     */
    //ubint ModBarrettSub(const ubint& b, const ubint& modulus,const ubint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Scalar modulus multiplication.
     *
     * @param &b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus multiplication operation.
     */
    ubint ModMul(const ubint& b, const ubint& modulus) const;

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
    ubint BModMul(const ubint& b, const ubint& modulus,const ubint& mu) const;
    ubint DBCModMul(const ubint& b, const ubint& modulus,const ubint& mu) const;

    /**
     * Scalar modular multiplication where Barrett modular reduction is used.
     *
     * @param &b is the scalar to multiply.
     * @param modulus is the modulus to perform operations with.
     * @param mu_arr is an array of the Barrett values of length BARRETT_LEVELS.
     * @return is the result of the modulus multiplication operation.
     */
    //ubint ModBarrettMul(const ubint& b, const ubint& modulus,const ubint mu_arr[BARRETT_LEVELS]) const;

    /**
     * Scalar modular exponentiation. Square-and-multiply algorithm is used.
     *
     * @param &b is the scalar to exponentiate.
     * @param modulus is the modulus to perform operations with.
     * @return is the result of the modulus exponentiation operation.
     */
    ubint ModExp(const ubint& b, const ubint& modulus) const;

    /**
     * Stores the based 10 equivalent/Decimal value of the ubint in a string object and returns it.
     *
     * @return value of this ubint in base 10 represented as a string.
     */
    const std::string ToString() const;		

    //Serialization functions

    const std::string Serialize() const;
    const char * Deserialize(const char * str);

    // helper functions

    /**
     * Tests whether the ubint is a power of 2.
     *
     * @param m_numToCheck is the value to check.
     * @return true if the input is a power of 2, false otherwise.
     */
    bool isPowerOfTwo(const ubint& m_numToCheck);

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
     * Convert a string representation of a binary number to a ubint.
     *
     * @param bitString the binary num in string.
     * @return the  number represented as a ubint.
     */
    static ubint BinaryStringToUbint(const std::string& bitString);

  
    /**
     * Test equality of the inputs.
     *
     * @param a second value to test.
     * @return true if the inputs are equal.
     */
    bool operator==(const ubint& a) const;

    /**
     * Test inequality of the inputs.
     *
     * @param a second value to test.
     * @return true if the inputs are inequal.
     */
    bool operator!=(const ubint& a) const;

    /**
     * Test if first input is great than the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is greater.
     */
    bool operator> (const ubint& a) const;

    /**
     * Test if first input is great than or equal to the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is greater than or equal to the second input.
     */
    bool operator>=(const ubint& a) const;

    /**
     * Test if first input is less than the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is lesser.
     */
    bool operator< (const ubint& a) const;

    /**
     * Test if first input is less than or equal to the second input.
     *
     * @param a second value to test.
     * @return true if the first inputs is less than or equal to the second input.
     */
    bool operator<=(const ubint& a) const;

    //overloaded binary operators based on integer arithmetic and comparison functions
    /**
     * Addition operation.
     *
     * @param a is the value to add.
     * @return is the result of the addition operation.
     */
    inline ubint operator+(const ubint &a) const {return this->Add(a);}

    /**
     * Subtraction operation.
     *
     * @param a is the value to subtract.
     * @return is the result of the subtraction operation.
     */
    inline ubint operator-(const ubint &a) const {return this->Sub(a);}

    /**
     * Multiplication operation.
     *
     * @param a is the value to multiply with.
     * @return is the result of the multiplication operation.
     */
    inline ubint operator*(const ubint &a) const {return this->Mul(a);}



    /**
     * Modulo operation. Classical modular reduction algorithm is used.
     *
     * @param a is the value to Mod.
     * @return is the result of the modulus operation.
     */
    inline ubint operator%(const ubint &a) const {return this->Mod(a);}

    /**
     * Division operation.
     *
     * @param a is the value to divide.
     * @param b is the value to divide by.
     * @return is the result of the integral part after division operation.
     */
    inline ubint operator/ (const ubint &a) const {return this->Div(a);}

    /**
     * Console output operation.
     *
     * @param os is the std ostream object.
     * @param ptr_obj is ubint to be printed.
     * @return is the ostream object.
     */
    template<typename limb_t_c>
    friend std::ostream& operator<<(std::ostream& os, const ubint<limb_t_c> &ptr_obj);
    
    //constant definations
        
    /**
     * Constant zero.
     */
    static const ubint ZERO;

    /**
     * Constant one.
     */
    static const ubint ONE;

    /**
     * Constant two.
     */
    static const ubint TWO;

    /**
     * Constant three.
     */
    static const ubint THREE;

    /**
     * Constant four.
     */
    static const ubint FOUR;

    /**
     * Constant five.
     */
    static const ubint FIVE;
    
    /**
     * Compares the current ubint to ubint a.
     *
     * @param a is the ubint to be compared with.
     * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
     */
    sint Compare(const ubint& a) const;

    /**
     *  Set this int to 1.
     */
    inline void SetIdentity() { *this = ubint::ONE; };

    /**
     * A zero allocator that is called by the Matrix class. It is used to initialize a Matrix of ubint objects.
     */
    static std::function<unique_ptr<ubint>()> Allocator;

    /**
     * Gets the MSB of the ubint from the internal value.
     */
    usint GetMSB();

    /**
     * Gets the state of the ubint from the internal value.
     */
    const std::string GetState()const;

  protected:
    
    /**
     * Converts the string v into base-r integer where r is equal to 2^bitwidth of limb data type.
     *
     * @param v The input string
     */
    void AssignVal(const std::string& v);

    /**
     * Sets the MSB to the correct value as computed from the internal value.
     */
    void SetMSB();

    /**
     * Sets the MSB to the correct value from the ubint.
     * @param guessIdxChar is the hint of the MSB position.
     */
    void SetMSB(usint guessIdxChar);

  private:
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
        

    /**
     * helper function for Div
     * @param defined in ubint.cpp
     */
    
    int divmnu_vect(ubint& q, ubint& r, const ubint& u, const ubint& v) const;


    //vector storing the native integers. stored little endian
    vector<limb_t> m_value;

    //variable that stores the MOST SIGNIFICANT BIT position in the
    //number. Note MSB(1) = 1 NOT 0
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
    //Todo remove this limitation
    static const usint m_numDigitInPrintval=1500;

    /**
     * function to return the ceiling of the number divided by the number of bits in the limb data type.
     * @param Number is the number to be divided.
     * @return the ceiling of Number/(bits in the limb data type)
     */
    static usint ceilIntByUInt(const limb_t Number);

    //currently unused array
    static const ubint *m_modChain;
		

    //public: 
  private: 
    /**
     * function to return the MSB of a 32 bit number.
     * @param x is the 32 bit integer.
     * @return the MSB position in the 32 bit number x. Note MSB(1) is 1 NOT zero!!!!!
     */
    static uint64_t GetMSB32(uint64_t x);
    /**
     * function to return the MSB of number.
     * @param x is the number.
     * @return the MSB position in the number x.Note MSB(1) is 1 NOT zero!!!!!
     */
		
    static usint GetMSBlimb_t(limb_t x);
		
		
    /**
     * function to return the MSB of 64 bit number.
     * @param x is the number.
     * @return the MSB position in the number x. Note MSB(1) is 1 NOT zero!!!!!
     */
    static uint64_t GetMSB64(uint64_t x);

    //Dlimb_t is the data type that has twice as many bits in the limb data type.
    typedef typename DoubleDataType<limb_t>::T Dlimb_t;

    //enum defination to represent the state of the ubint.
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
     * function that returns the ubint after multiplication by b.
     * @param b is the number to be multiplied.
     * @return the ubint after the multiplication.
     */
    ubint MulIntegerByLimb(limb_t b) const;
		
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


  /**
   * Division operation.
   *
   * @param a is the value to divide.
   * @param b is the value to divide by.
   * @return is the result of the division operation.
   */
  //todo: does this go here?
  template<typename limb_t>
    inline ubint<limb_t> operator/(const ubint<limb_t> &a, const ubint<limb_t> &b) {return a.Div(b);}
  
}//namespace ends

#endif //LBCRYPTO_MATH_EXPINT32_UBINT_H

