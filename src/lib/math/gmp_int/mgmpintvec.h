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

#ifndef LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H
#define LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H

#include <iostream>
#include <vector>

#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include <initializer_list>
#include "gmpintvec.h"
#include <NTL/vector.h>
#include <NTL/vec_ZZ.h>
#include <NTL/SmartPtr.h>
#include <NTL/vec_ZZ_p.h>
/**
 * @namespace NTL
 * The namespace of this code
 */
namespace NTL {
  /**
 * @brief The class for representing vectors of ubint with associated modulo math
 */
//note this inherits from gmpintvec

//JSON FACILITY

template<class myT>
  class myVecP : public NTL::vec_ZZ_p {
//    class myVecP : public lbcrypto::Serializable


public:
  
   myVecP() : Vec<myT>() {};
   myVecP(usint n) : Vec<myT>(INIT_SIZE, n) {}; // adapter kit
   myVecP(INIT_SIZE_TYPE, long n) : Vec<myT>(INIT_SIZE, n) {};
   myVecP(INIT_SIZE_TYPE, long n, const myT& a) : Vec<myT>(INIT_SIZE, n, a) {};  



   myVecP(const NTL::Vec<myT> &a) : Vec<myT>(a) {};
   myVecP(NTL::Vec<ZZ> &a) : Vec<ZZ>(a) {};
   myVecP(NTL::Vec<ZZ> &&a) : Vec<ZZ>(a) {};
   myVecP(const NTL::Vec<ZZ> &a) : Vec<ZZ>(a) {};

   myVecP(NTL::Vec<myT> &&a) : Vec<myT>(a) {};

  //destructor
  ~myVecP();

  //adapters
  myVecP(std::vector<std::string>& s);
  const myVecP& operator=(std::initializer_list<myT> rhs);
  const myVecP& operator=(std::initializer_list<usint> rhs);
  const myVecP& operator=(std::initializer_list<std::string> rhs);
  const myVecP& operator=(std::initializer_list<const char *> rhs);
  const myVecP& operator=(myT &rhs);
  const myVecP& operator=(const myT &rhs);
  const myVecP& operator=(unsigned int &rhs);
  const myVecP& operator=(unsigned int rhs);

  void clear(myVecP& x); //why isn't this inhereted?

  inline usint size() {return this->length();};
  void SetValAtIndex(usint index, const myT&value);
  void SetValAtIndex(usint index, const char *s);
  void SetValAtIndex(usint index, const std::string& str);
  const myT& GetValAtIndex(size_t index) const;

  inline void push_back(const myT& a) { this->append(a);};

  static inline myVecP Single(const myT& val, const myT&modulus) {
    myVecP vec(1);
    vec.m_data[0]=val;
    vec.SetModulus(modulus);
    return vec;
  }

#if 0 //unifdef as this gets modified, comes from gmpintvec


  //arithmetic
  //scalar modulus

  myVecP operator%(const myT& b) const; 

  inline myVecP Mod(const myZZ& b) const { return (*this)%b;};

  //scalar modulo assignment
  inline myVecP& operator%=(const myT& a)
  { 
    unsigned int n = this->length();
    for (unsigned int i = 0; i < n; i++){
      (*this)[i]%=a;
    }
    return *this;
  };



  inline myVecP& operator+=(const myVecP& a) {
    add(*this, *this, a);
    return *this;
  };

  //scalar addition assignment
  inline myVecP& operator+=(const myT& a)
  { 
    unsigned int n = this->length();
    for (unsigned int i = 0; i < n; i++){
      (*this)[i]+=a;
    }
    return *this;
  };

  myVecP operator+(const myVecP& b) const;
  myVecP operator+(const myT& b) const;

  inline myVecP Add(const myT& b) const { return (*this)+b;};

  void add(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

  //vector add
  inline myVecP Add(const myVecP& b) const { return (*this)+b;};

  //Subtraction
  inline myVecP& operator-=(const myVecP& a)
  { 
    sub(*this, *this, a);
    return *this;
  };

  inline myVecP& operator-=(const myT& a)
  { 
    unsigned int n = this->length();
    for (unsigned int i = 0; i < n; i++){
      (*this)[i]-=a;
    }
    return *this;
  };

  
  myVecP operator-(const myVecP& b) const;
  myVecP operator-(const myT& a) const;

  //scalar
  inline myVecP Sub(const myT& b) const { return (*this)-b;};
  //vector
  inline myVecP Sub(const myVecP& b) const { return (*this)-b;};

  //deprecated vector
  inline myVecP Minus(const myVecP& b) const { return (*this)-b;};

  void sub(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural

  //Multiplication
  inline myVecP& operator*=(const myVecP& a)
  { 
    mul(*this, *this, a);
    return *this;
  };

  inline myVecP& operator*=(const myT& a)
  { 
    unsigned int n = this->length();
    for (unsigned int i = 0; i < n; i++){
      (*this)[i]*=a;
    }
    return *this;
  };

  
  myVecP operator*(const myVecP& b) const;
  myVecP operator*(const myT& a) const;
  //scalar
  inline myVecP Mul(const myT& b) const { return (*this)*b;};
  //vector
  inline myVecP Mul(const myVecP& b) const { return (*this)*b;};
  void mul(myVecP& x, const myVecP& a, const myVecP& b) const; //define procedural


  //not tested yet

  //scalar then vector
  //note a more efficient means exists for these
  inline myVecP ModAdd(const myT& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};
  inline myVecP ModAdd(const myVecP& b, const myZZ& modulus) const {return ((*this)+b)%modulus;};

  // note that modsub requires us to use the NTL signed subtraction 
  // rather than the Palisade unsigned subtraction 
  inline myVecP ModSub(const myT& b, const myZZ& modulus) const 
  {
    unsigned int n = this->length();
    myVecP<myT> res(n);
    for (unsigned int i = 0; i < n; i++){
      NTL_NAMESPACE::sub(res[i],(*this)[i],b);
      res[i] = res[i]%modulus;
    }
    return(res);
  };

  inline myVecP ModSub(const myVecP& b, const myZZ& modulus) const 
  {
    unsigned int n = this->length();
    myVecP<myT> res(n);
    for (unsigned int i = 0; i < n; i++){
      NTL_NAMESPACE::sub(res[i],(*this)[i],b[i]);
      res[i] = res[i]%modulus;
    }
    return(res);
  };

  inline myVecP ModMul(const myT& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};
  inline myVecP ModMul(const myVecP& b, const myZZ& modulus) const {return ((*this)*b)%modulus;};


#endif



private:
  myT m_modulus;
  enum State {
    INITIALIZED, GARBAGE
  };
  //enum to store the state of the
  State m_modulus_state;


}; //template class ends

} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_MGMPINTVEC_H
