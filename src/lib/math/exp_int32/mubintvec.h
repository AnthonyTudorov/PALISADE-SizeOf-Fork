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

#ifndef LBCRYPTO_MATH_EXPINT32_MUBINTVEC_H
#define LBCRYPTO_MATH_EXPINT32_MUBINTVEC_H

#include <iostream>
#include <vector>

//#include "binmat.h"
#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include "ubintvec.h"

/**
 * @namespace exp_int32
 * The namespace of exp_int32
 */
namespace exp_int32 {
/**
 * @brief The class for representing vectors of ubint with associated math
 */
//JSON FACILITY
template<class bint_el_t>
class mubintvec: public lbcrypto::Serializable, public ubintvec<bint_el_t>
//    class mubintvec : public lbcrypto::Serializable
{
public:
  /**
   * Basic constructor.
   */
  explicit mubintvec();

  //	static inline mubintvec Single(const bint_el_t& val) { //not sure this is needed
  //mubintvec vec(1, modulus);
  //vec.SetValAtIndex(0, val);
  //return vec;
  //}

  /**
   * Basic constructor for specifying the length of the vector.
   *
   * @param length is the length of the mubintvec, in terms of the number of entries.
   */
  explicit mubintvec(usint length);

  /**
   * Basic constructor for specifying the length of the vector.
   *
   * @param length is the length of the mubintvec, in terms of the number of entries.
   * @param modulus is the modulus of the entries in the vector.
   */
  explicit mubintvec(const usint length, const usint &modulus);
  /**
   * Basic constructor for specifying the length of the vector.
   *
   * @param length is the length of the mubintvec, in terms of the number of entries.
   * @param modulus is the modulus of the entries in the vector.  	         */
  explicit mubintvec(const usint length, const bint_el_t & modulus);

  /**
   * Basic constructor for specifying the length of the vector.
   *
   * @param length is the length of the mubintvec, in terms of the number of entries.
   * @param modulus is the modulus of the entries in the vector.  	         */
  explicit mubintvec(const usint length, const std::string& modulus);

  // constructor specifying the mubintvec as a vector of strings and modulus
  explicit mubintvec(const std::vector<std::string> &s, const bint_el_t &modulus);

  // constructor specifying the mubintvec as a vector of strings and modulus
  explicit mubintvec(const std::vector<std::string> &s, const std::string &modulus);

  /**
   * Basic constructor for copying a vector
   *
   * @param rhs is the mubintvec to be copied.
   */
  explicit mubintvec(const mubintvec& rhs);

  /**
   * Basic move constructor for moving a vector
   *
   * @param &&rhs is the mubintvec to be moved.
   */
  mubintvec(mubintvec &&rhs);      //move copy constructor

  /**
   * Assignment operator
   *
   * @param &rhs is the mubintvec to be assigned from.
   * @return assigned mubintvec ref.
   */
  const mubintvec& operator=(const mubintvec &rhs);

  /**
   * move copy contructor
   *
   * @param &rhs is the mubintvec to move
   * @return the return value.
   */
  const mubintvec& operator=(mubintvec &&rhs);

  /**
   * ???
   *
   * @param &&rhs is the mubintvec to test equality with.
   * @return the return value.
   */

  inline bool operator==(const mubintvec &b) const {
    if (this->ubintvec<bint_el_t>::GetLength() != b.GetLength()) {
      return false;
    }      //todo replace with vector equality check.
    if (this->m_modulus != b.m_modulus)
      return false;
    for (size_t i = 0; i < this->GetLength(); ++i) {
      if (this->GetValAtIndex(i) != b.GetValAtIndex(i)) {
        return false;
      }
    }
    return true;
  }

  //assignment from usint
  inline const mubintvec& operator=(usint val) {
    //todo change this. it
    *this->m_data.at(0) = val;
    for (size_t i = 1; i < *this->ubintvec<bint_el_t>::GetLength(); ++i) {
      *this->m_data[i] = 0;
    }
    m_modulus();
    m_modulus_state = GARBAGE;

    return *this;
  }

  inline bool operator!=(const mubintvec &b) const {
    return !(*this == b);
  }

  /**
   * Destructor.
   */
  virtual ~mubintvec();

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
  friend std::ostream& operator<<(std::ostream& os,
      const mubintvec<bint_el_t_c> &ptr_obj);

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const uint& value);

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const bint_el_t& value);

  /**
   * Sets the vector modulus.
   *
   * @param value is the value to set.
   */
  void SetModulus(const std::string& value);

  /**
   * Gets the vector modulus.
   *
   * @return the vector modulus.
   */
  const bint_el_t& GetModulus() const;

  //METHODS

  /**
   * returns the vector modulus with respect to the input value.
   *
   * @param modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   * side effect it resets the vector modulus to modulus
   */
  mubintvec Mod(const bint_el_t& modulus) const;

    /**
   * vector scalar %=
   *
   * @param &modulus is the new modulus value
   * @return is the result of the mod operation.
   */
  const mubintvec& operator%=(const bint_el_t& modulus);

  //scalar operations

  /**
   * Scalar addition.
   *
   * @param &b is the scalar to modulo add at all locations.
   * @return is the result of the addition operation.
   */
  mubintvec ModAdd(const bint_el_t &b) const;

  /**
   * Scalar subtraction.
   *
   * @param &b is the scalar to modulo subtract from all locations.
   * @return is the result of the subtraction operation.
   */
  mubintvec ModSub(const bint_el_t &b) const;

  /**
   * Scalar multiplication.
   *
   * @param &b is the scalar to modulo multiply at all locations.
   * @return is the result of the multiplication operation.
   */
  mubintvec ModMul(const bint_el_t &b) const;

  /**
   * Scalar exponentiation.
   *
   * @param &b is the scalar to modulo exponentiate at all locations.
   * @return is the result of the exponentiation operation.
   */
  mubintvec ModExp(const bint_el_t &b) const;

  //vector operations

  //component-wise addition
  /**
   * vector addition.
   *
   * @param &b is the vector to add at all locations.
   * @return is the result of the addition operation.
   */
  mubintvec ModAdd(const mubintvec &b) const;

  /**
   * vector +=
   *
   * @param &b is the vector to modadd to lhs
   * @return is the result of the addition operation.
   */
  const mubintvec& operator+=(const mubintvec &b);

  //component-wise subtraction

  /**
   * Vector subtraction.
   *
   * @param &b is the vector to subtract from lhs
   * @return is the result of the subtraction operation.
   * TODO: need to define what happens when b > a!
   */
  mubintvec ModSub(const mubintvec &b) const;

  /**
   * vector -=
   *
   * @param &b is the vector to mod subtract from lhs
   * @return is the result of the addition operation.
   * TODO: need to define what happens when b > a!!
   */
  const mubintvec& operator-=(const mubintvec &b);

  //component-wise multiplication

  /**
   * Vector multiplication.
   *
   * @param &b is the vector to multiply.
   * @return is the result of the multiplication operation.
   */
  mubintvec ModMul(const mubintvec &b) const;

  // auxiliary functions

  //MANIPULATORS
  //useful for storing the results in the current instance of the class
  //they can also be added for scalar operations and modulo operation
  // mubintvec&  operator+=(const mubintvec& t) {*this = *this+t; return *this;}
  //mubintvec&  operator*=(const mubintvec& t) {return *this = *this*t;}
  //Gyana to add -= operator

  //JSON FACILITY
  /**
   * Implemented by this object only for inheritance requirements of abstract class Serializable.
   *
   * @param serializationMap stores this object's serialized attribute name value pairs.
   * @return map passed in.
   */
  std::unordered_map<std::string, std::unordered_map<std::string, std::string>> SetIdFlag(
      std::unordered_map<std::string,
          std::unordered_map<std::string, std::string>> serializationMap,
      std::string flag) const;

  //JSON FACILITY
  /**
   * Stores this object's attribute name value pairs to a map for serializing this object to a JSON file.
   *
   * @param serializationMap stores this object's serialized attribute name value pairs.
   * @return map updated with the attribute name value pairs required to serialize this object.
   */
  std::unordered_map<std::string, std::unordered_map<std::string, std::string>> Serialize(
      std::unordered_map<std::string,
          std::unordered_map<std::string, std::string>> serializationMap,
      std::string fileFlag) const;

  //JSON FACILITY
  /**
   * Sets this object's attribute name value pairs to deserialize this object from a JSON file.
   *
   * @param serializationMap stores this object's serialized attribute name value pairs.
   */
  void Deserialize(
      std::unordered_map<std::string,
          std::unordered_map<std::string, std::string>> serializationMap);

private:
  bint_el_t m_modulus;
  enum State {
    INITIALIZED, GARBAGE
  };
  //enum to store the state of the
  State m_modulus_state;

};

//BINARY OPERATORS
  /**
   *   scalar modulo
   *
   * @param &a is the input vector to modulo.
   * @param &modulus is the input bint modulus
   * @return is the result of the modulo operation.
   */
  template<class bint_el_t>
  inline mubintvec<bint_el_t> operator%(const mubintvec<bint_el_t> &a,
      const bint_el_t &modulo) {
    return a.Mod(modulo);
  }


/**
 *   scalar modulo addition.
 *
 * @param &a is the input vector to add.
 * @param &b is the input bint to add.
 * @return is the result of the modulo addition operation.
 */
template<class bint_el_t>
inline mubintvec<bint_el_t> operator+(const mubintvec<bint_el_t> &a,
    const bint_el_t &b) {
  return a.ModAdd(b);
}

/**
 *   scalar modulo subtraction
 *
 * @param &a is the input vector to subtract.
 * @param &b is the input bint to subtract.
 * @return is the result of the modulo subtraction operation.
 */
template<class bint_el_t>
inline mubintvec<bint_el_t> operator-(const mubintvec<bint_el_t> &a,
    const bint_el_t &b) {
  return a.ModSub(b);
}

/**
 *  scalar modulo multiplication.
 *
 * @param &a is the input vector to multiply.
 * @param &i is the input integer to multiply.
 * @return is the result of the modulo multiplication operation.
 */
template<class bint_el_t>
inline mubintvec<bint_el_t> operator*(const mubintvec<bint_el_t> &a,
    const bint_el_t &i) {
  return a.ModMul(i);
}

/**
 *  vector modulo addition.
 *
 * @param &a is the first input vector to add.
 * @param &b is the second input vector to add.
 * @return is the result of the modulo addition operation.
 */
template<class bint_el_t>
inline mubintvec<bint_el_t> operator+(const mubintvec<bint_el_t> &a,
    const mubintvec<bint_el_t> &b) {
  return a.ModAdd(b);
}

/**
 *  vector subtraction.
 *
 * @param &a is the first input vector to subtract.
 * @param &b is the second input vector to subtract.
 * @return is the result of the subtraction operation.
 */
template<class bint_el_t>
inline mubintvec<bint_el_t> operator-(const mubintvec<bint_el_t> &a,
    const mubintvec<bint_el_t> &b) {
  return a.ModSub(b);
}

/**
 *  vector multiplication.
 *
 * @param &a is the first input vector to multiply.
 * @param &b is the second input vector to multiply.
 * @return is the result of the multiplication operation.
 */
template<class bint_el_t>
inline mubintvec<bint_el_t> operator*(const mubintvec<bint_el_t> &a,
    const mubintvec<bint_el_t> &b) {
  return a.ModMul(b);
}

} // namespace lbcrypto ends

#endif // LBCRYPTO_MATH_EXPINT32_MUBINTVEC_H
