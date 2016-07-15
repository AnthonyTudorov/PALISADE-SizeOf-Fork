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
 * This file contains ubintvec, a <vector> of ubint, with associated
 * math operators.  
 * NOTE: this has been refactored so that implied modulo (ring)
 * aritmetic is in mbintvec
 *
 */

#ifndef LBCRYPTO_MATH_EXPINT32_UBINTVEC_H
#define LBCRYPTO_MATH_EXPINT32_UBINTVEC_H


#include <iostream>
#include <vector>

//#include "binmat.h"
#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include "ubint.h"

/**
 * @namespace exp_int32
 * The namespace of exp_int32
 */
namespace exp_int32 {
  /**
   * @brief The class for representing vectors of ubint with associated math
   */
  //JSON FACILITY
  template <class bint_el_t>
    class ubintvec : public lbcrypto::Serializable
    {
    public:
      /**
       * Basic constructor.	  	  
       */
      explicit ubintvec();

      //	static inline ubintvec Single(const bint_el_t& val) { //not sure this is needed
      //ubintvec vec(1, modulus);
      //vec.SetValAtIndex(0, val);
      //return vec;
      //}

      /**
       * Basic constructor for specifying the length of the vector.
       *
       * @param length is the length of the ubintvec, in terms of the number of entries.
       */
      explicit ubintvec(usint length);


      /**
       * constructor specifying the vector from a vector of strings.
       *
       * @param s is the vector of strings containing text version of numbers
       */

      explicit ubintvec(std::vector<std::string>& s);

      /**
       * Basic constructor for copying a vector
       *
       * @param rhs is the ubintvec to be copied.
       */
      explicit ubintvec(const ubintvec& rhs);

      /**
       * Basic move constructor for moving a vector
       *
       * @param &&rhs is the ubintvec to be moved.
       */
      ubintvec(ubintvec &&rhs);//move copy constructor

      /**
     * Assignment operator
     *
     * @param &rhs is the ubintvec to be assigned from.
     * @return assigned ubintvec ref.
     */
      const ubintvec&  operator=(const ubintvec &rhs);



      /**
       * move copy contructor
       *
       * @param &rhs is the ubintvec to move
       * @return the return value.	  
       */
      const ubintvec&  operator=(ubintvec &&rhs);
      
      /**
       * ???
       *
       * @param &&rhs is the ubintvec to test equality with.
       * @return the return value.	  
       */      

      inline bool operator==(const ubintvec &b) const {
        if (this->GetLength() != b.GetLength()) {
          return false;
        }//todo replace with vector equality check.
        for (size_t i = 0; i < this->GetLength(); ++i) {
          if (this->GetValAtIndex(i) != b.GetValAtIndex(i)) {
            return false;
          }
        }
        return true;
      }

      //assignment from usint
      inline const ubintvec& operator=(usint val) {
        //todo change this. it
        *this->m_data.at(0) = val;
        for (size_t i = 1; i < GetLength(); ++i) {
          *this->m_data[i] = 0;
        }
        return *this;
      }


      inline bool operator!=(const ubintvec &b) const {
        return !(*this == b);
      }

      /**
       * Destructor.	  
       */
      virtual ~ubintvec();

      //ACCESSORS

      //change to ostream?
      /**
       * ???
       *
       * @param os ???.
       * @param &ptr_obj ???.
       * @return the return value.	  
       */
      template<class bint_el_t_c>
	friend std::ostream& operator<<(std::ostream& os, const ubintvec<bint_el_t_c> &ptr_obj);

      /**
       * Sets a value at an index.
       * NOTE DEPRECATED BY []
       * @param index is the index to set a value at.
       * @param value is the value to set at the index.
       */
      void SetValAtIndex(usint index, const bint_el_t& value);

      /**
       * Sets a value at an index.
       * NOTE DEPRECATED BY []
       * @param index is the index to set a value at.
       * @param str is the string representation of the value to set at the index.
       */
      void SetValAtIndex(usint index, const std::string& str);

      /**
       * Gets a value at an index.
       * NOTE DEPRECATED BY []
       * @param index is the index to get a value at.
       * @return is the value at the index. return NULL if invalid index.
       */
      const bint_el_t& GetValAtIndex(usint index) const;


      /**
       * operators to get a value at an index.
       * @param idx is the index to get a value at.
       * @return is the value at the index. return NULL if invalid index.
       */
      inline bint_el_t& operator[](std::size_t idx) {return (this->m_data[idx]);}
      //ubintvec<bint_el_t>& operator[](std::size_t idx);
      inline const bint_el_t& operator[](std::size_t idx) const {return (this->m_data[idx]);}
      //const ubintvec<bint_el_t>& operator[](std::size_t idx) const;

      //inline ubintvec<bint_el_t>& operator[](usint idx) {return &(this->m_data[idx]);}
      //inline const ubintvec<bint_el_t>& operator[](usint idx) const {return &(this->m_data[idx]);}


      /**
       * Gets the vector length.
       * NOTE DEPRECATED BY size()
       * @return the vector length.
       */
      usint GetLength() const;
      usint size() const;
	
      //METHODS

      /**
       * returns the vector modulus with respect to the input value.
       *
       * @param modulus is the modulus to perform.
       * @return is the result of the modulus operation.
       */
      ubintvec Mod(const bint_el_t& modulus) const;

       /**
        * vector scalar %=
        *
        * @param modulus is the  modulus value
        * @return is the result of the mod operation.
        */
      const ubintvec& operator%=(const bint_el_t& modulus);



      //scalar operations

      /**
       * Scalar addition.
       *
       * @param &b is the scalar to add at all locations.
       * @return is the result of the addition operation.
       */
      ubintvec Add(const bint_el_t &b) const;

      /**
       * Scalar subtraction.
       *
       * @param &b is the scalar to subtract from all locations.
       * @return is the result of the subtraction operation.
       */
      ubintvec Sub(const bint_el_t &b) const;

      /**
       * Scalar multiplication.
       *
       * @param &b is the scalar to multiply at all locations.
       * @return is the result of the multiplication operation.
       */
      ubintvec Mul(const bint_el_t &b) const;

      /**
       * Scalar exponentiation.
       *
       * @param &b is the scalar to exponentiate at all locations.
       * @return is the result of the exponentiation operation.
       */
      ubintvec Exp(const bint_el_t &b) const;

      //vector operations

      //component-wise addition
      /**
       * vector addition.
       *
       * @param &b is the vector to add at all locations.
       * @return is the result of the addition operation.
       */
      ubintvec Add(const ubintvec  &b) const;

      /**
       * vector +=
       *
       * @param &b is the vector to add to lhs
       * @return is the result of the addition operation.
       */
      const ubintvec& operator+=(const ubintvec &b);

      //component-wise subtraction

      /**
       * Vector subtraction.
       *
       * @param &b is the vector to subtract from lhs
       * @return is the result of the subtraction operation.
       * TODO: need to define what happens when b > a!
       */
      ubintvec Sub(const ubintvec &b) const;

      /**
       * vector -=
       *
       * @param &b is the vector to subtract from lhs
       * @return is the result of the addition operation.
       * TODO: need to define what happens when b > a!!
       */
      const ubintvec& operator-=(const ubintvec &b);


      //component-wise multiplication

      /**
       * Vector multiplication.
       *
       * @param &b is the vector to multiply.
       * @return is the result of the multiplication operation.
       */
      ubintvec Mul(const ubintvec &b) const;

      /**
       * Scalar modular addition.
       *
       * @param &b is the scalar to add to all elements of this.
       * @param modulus is the modulus to perform operations with.
       * @return result of the modulus addition operation.
       */
      ubintvec ModAdd(const bint_el_t& b, const bint_el_t& modulus) const;


      /**
       * Scalar modular subtraction.
       *
       * @param &b is the scalar to subtract from all elements of this.
       * @param modulus is the modulus to perform operations with.
       * @return result of the modulus subtraction operation.
       */
      ubintvec ModSub(const bint_el_t& b, const bint_el_t& modulus) const;


      /**
       * Scalar modular multiplication.
       *
       * @param &b is the scalar to multiply by all elements of this.
       * @param modulus is the modulus to perform operations with.
       * @return result of the modulus multiplication operation.
       */
      ubintvec ModMul(const bint_el_t& b, const bint_el_t& modulus) const;

      /**
       * vector modulus addition.
       *
       * @param &b is the vector to add elementwise to all locations
       * @param modulus is the modulus to perform operations with.
       * @return is the result of the modulus vector addition operation.
       */
      ubintvec ModAdd(const ubintvec &b, const bint_el_t& modulus) const;

      /**
       * vector modulus subtraction
       *
       * @param &b is the vector to subtract elementwise from all locations
       * @param modulus is the modulus to perform operations with.
       * @return is the result of the modulus vector subtraction operation.
       */
      ubintvec ModSub(const ubintvec &b, const bint_el_t& modulus) const;

      /**
       * vector modulus addition.
       *
       * @param &b is the vector to multiply elementwise to all locations
       * @param modulus is the modulus to perform operations with.
       * @return is the result of the modulus vector mulitplication operation.
       */
      ubintvec ModMul(const ubintvec &b, const bint_el_t& modulus) const;

      // auxiliary functions
      /**
       * Returns a vector of digit at a specific index for all entries for a given number base.
       *
       * @param index is the index to return the digit from in all entries.
       * @param base is the base to use for the operation.
       * @return is the resulting vector.
       */

      ubintvec GetDigitAtIndexForBase(usint index, usint base) const;

      //MANIPULATORS
      //useful for storing the results in the current instance of the class
      //they can also be added for scalar operations and modulo operation
      // ubintvec&  operator+=(const ubintvec& t) {*this = *this+t; return *this;}
      //ubintvec&  operator*=(const ubintvec& t) {return *this = *this*t;}
      //Gyana to add -= operator

      //JSON FACILITY
      /**
       * Implemented by this object only for inheritance requirements of abstract class Serializable.
       *
       * @param serializationMap stores this object's serialized attribute name value pairs.
       * @return map passed in.
       */
      std::unordered_map <std::string, std::unordered_map <std::string, std::string>> SetIdFlag(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string flag) const;

      //JSON FACILITY
      /**
       * Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
       *
       * @param serializationMap stores this object's serialized attribute name value pairs.
       * @return map updated with the attribute name value pairs required to serialize this object.
       */
      std::unordered_map <std::string, std::unordered_map <std::string, std::string>> Serialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap, std::string fileFlag) const;

      //JSON FACILITY
      /**
       * Sets this object's attribute name value pairs to deserialize this object from a JSON file.
       *
       * @param serializationMap stores this object's serialized attribute name value pairs.
       */
      void Deserialize(std::unordered_map <std::string, std::unordered_map <std::string, std::string>> serializationMap);

    protected:
      std::vector<bint_el_t> m_data;
      bool IndexCheck(usint) const;
    };

  //BINARY OPERATORS
  /**
   *   scalar modulo operator %
   *
   * @param &a is the input vector to modulo.
   * @param &modulus is the input bint modulus
   * @return is the result of the modulo operation.
   */
  template<class bint_el_t>
  inline ubintvec<bint_el_t> operator%(const ubintvec<bint_el_t> &a,
      const bint_el_t &modulo) {
    return a.Mod(modulo);
  }

  /**
   *   scalar addition.
   *
   * @param &a is the input vector to add.
   * @param &i is the input integer to add.
   * @return is the result of the addition operation.
   */
  template<class bint_el_t>
    inline ubintvec<bint_el_t> operator+(const ubintvec<bint_el_t> &a, const bint_el_t &i) {return a.Add(i);}

  /**
   *   scalar subtraction
   *
   * @param &a is the input vector to subtract.
   * @param &i is the input integer to subtract.
   * @return is the result of the subtraction operation.
   */
  template<class bint_el_t>
    inline ubintvec<bint_el_t> operator-(const ubintvec<bint_el_t> &a, const bint_el_t &i) {return a.Sub(i);}

  /**
   *  scalar multiplication.
   *
   * @param &a is the input vector to multiply.
   * @param &i is the input integer to multiply.
   * @return is the result of the multiplication operation.
   */
  template<class bint_el_t>
    inline ubintvec<bint_el_t> operator*(const ubintvec<bint_el_t> &a, const bint_el_t &i) {return a.Mul(i);}

  /**
   *  vector addition.
   *
   * @param &a is the first input vector to add.
   * @param &b is the second input vector to add.
   * @return is the result of the addition operation.
   */
  template<class bint_el_t>
    inline ubintvec<bint_el_t> operator+(const ubintvec<bint_el_t> &a, const ubintvec<bint_el_t> &b) {return a.Add(b);}

  /**
   *  vector subtraction.
   *
   * @param &a is the first input vector to subtract.
   * @param &b is the second input vector to subtract.
   * @return is the result of the subtraction operation.
   */
  template<class bint_el_t>
    inline ubintvec<bint_el_t> operator-(const ubintvec<bint_el_t> &a, const ubintvec<bint_el_t> &b) {return a.Sub(b);}

  /**
   *  vector multiplication.
   *
   * @param &a is the first input vector to multiply.
   * @param &b is the second input vector to multiply.
   * @return is the result of the multiplication operation.
   */
  template<class bint_el_t>
    inline ubintvec<bint_el_t> operator*(const ubintvec<bint_el_t> &a, const ubintvec<bint_el_t> &b) {return a.Mul(b);}

  /**
   *  vector index
   *
   * @param &i is the index into the ubintvec
   * @return is the result of the index operation.
   */


} // namespace lbcrypto ends

#endif // LBCRYPTO_MATH_EXPINT32_UBINTVEC_H
