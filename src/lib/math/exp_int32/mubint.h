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

#include "ubint.h"
/**
 *@namespace exp_int32
 * The namespace of this code
 */
namespace exp_int32{

  /**
   * @brief Main class for modulus, implemented as a uint<limb_t>
   * @tparam limb_t native unsigned integer type
   */

  template<typename limb_t>
    class modulus: ubint<limb_t>
    {
    public:
      modulus(); //note always fails.

    /**
     * Basic constructor for specifying the modulus from a string of decimal digits.
     *
     * @param str is the initial integer represented as a string.
     */
      explicit modulus(const std::string& str);

    /**
     * Basic constructor for initializing modulus from an unsigned integer.
     *
     * @param init is the initial unsigned integer.
     */
    explicit modulus(usint init);
    /**
     * Basic constructor for initializing big modulus from a ubint refernce.
     *
     * @param init is the initial ubint.
     */
    explicit modulus(ubint& init);

    /**
     * Basic constructor for copying a modulus
     *
     * @param rhs is the modulus to be copied.
     */
    explicit modulus(const modulus& rhs);

    /**
     * Basic constructor for move copying a modulus
     *
     * @param &&rhs is the modulus to be moved from.
     */
    modulus(modulus&& rhs);

    /**
     * Destructor.
     */
    ~modulus();

    private:


    };




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
     * Basic constructor for copying a mubint
     *
     * @param rhs is the mubint to be copied.
     */
    explicit mubint(const ubint& rhs, modulus &m);

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
    void PrintModulusLimbsInDec() const;

   /**
    * Prints the value of the vector of limbs to console in hex format
    */
    void PrintModulusLimbsInHex() const;

    /**
     * Basic set method for setting the value of a mubint
     *
     * @param str is the string representation of the mubint to be copied.
     */
    void SetModulusValue(const std::string& str);
        
    /**
     * Basic set method for setting the value of a mubint
     *
     * @param a is the mubint representation of the mubint to be assigned.
     */
    void SetModulusValue(const mubint& a);

        
    /**
     * Returns the MSB location of the value.
     *
     * @return the index of the most significant bit.
     */
    usint GetModulusMSB()const;

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
    usint ConvertModulusToUsint() const;
    
    /**
     * Converts the value to a usint. Soon to be DEPRECATED, because Int is not usint
     * if the mubint is larger than the max value representable
     * it is truncated to the least significant bits that fit
     * @return the int representation of the value as usint.
     */
    usint ConvertModulusToInt() const;

    /**
     * Converts the value to a uint32_t.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * @return the int representation of the value as uint32_t
     */
    uint32_t ConvertModulusToUint32() const;
    
    /**
     * Converts the value to a uint64_t.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     * @return the int representation of the value as uint64_t
     */
    uint64_t ConvertModulusToUint64() const;

    /**
     * Converts the value to a float
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return float representation of the value.
     */
    float ConvertModulusToFloat() const;

    /**
     * Converts the value to an double.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return double representation of the value.
     */
    double ConvertModulusToDouble() const;


    /**
     * Converts the value to an long double.
     * if the mubint is larger than the max value representable
     * std::out_of_range is thrown
     * if conversion fails std::invalid_argment is thrown 
     *
     * @return long double representation of the value.
     */
    long double ConvertModulusToLongDouble() const;

    /**
     * Convert a value from an unsigned int to a mubint.
     *
     * @param m the value to convert from.
     * @return int represented as a mubint.
     */
    static mubint intTomubint(usint m);

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

    /**
     * Division operation.
     *
     * @param b of type mubint is the value to divide by.
     * @return result of the division operation.
     */
    mubint DividedBy(const mubint& b) const;

    /**
     * Stores the based 10 equivalent/Decimal value of the mubint in a string object and returns it.
     *
     * @return value of this mubint in base 10 represented as a string.
     */
    const std::string ToString() const;		


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
     * Compares the current mubint to mubint a.
     *
     * @param a is the mubint to be compared with.
     * @return  -1 for strictly less than, 0 for equal to and 1 for strictly greater than conditons.
     */
    sint Compare(const mubint& a) const;

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
    void AssignModulusVal(const std::string& v);

    /**
     * Sets the MSB to the correct value from the mubint.
     */
    void SetModulusMSB();

    /**
     * Sets the MSB to the correct value from the mubint.
     * @param guessIdxChar is the hint of the MSB position.
     */
    void SetMSB(usint guessIdxChar);

    //  private:
  public: //todo for debug onlhy

    //pointer to the array storing the modulus
    ubint modulus;

  public: 

  //  private:
  public:  //todo: changed only for debug

    //enum defination to represent the state of the mubint.
    enum State{
      INITIALIZED,GARBAGE
    };
    //enum to store the state of the 
    State m_state;

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

