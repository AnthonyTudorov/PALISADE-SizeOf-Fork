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

#ifndef LBCRYPTO_MATH_GMPINT_GMPINTVEC_H
#define LBCRYPTO_MATH_GMPINT_GMPINTVEC_H


#include <iostream>
#include <vector>

//#include "binmat.h"
#include "../../utils/inttypes.h"
#include "../../utils/serializable.h"
#include <initializer_list>
#include "gmpint.h"
#include <NTL/vec_ZZ.h>
#include <NTL/vector.h>


/**
 * @namespace NTL
 * The namespace of this code
 */
namespace NTL {
  /**
   * @brief The class for representing vectors of ubint with associated math
   */
  //JSON FACILITY

template<class myT>
  class myVec : public NTL::Vec<myT> {

 public:
  
   myVec() : Vec<myT>() {};
   myVec(usint n) : Vec<myT>(INIT_SIZE, n) {}; // adapter kit
   myVec(INIT_SIZE_TYPE, long n) : Vec<myT>(INIT_SIZE, n) {};
   myVec(INIT_SIZE_TYPE, long n, const myT& a) : Vec<myT>(INIT_SIZE, n, a) {};  



   myVec(const NTL::Vec<myT> &a) : Vec<myT>(a) {};
   myVec(NTL::Vec<ZZ> &a) : Vec<ZZ>(a) {};
   myVec(const NTL::Vec<ZZ> &a) : Vec<ZZ>(a) {};

   myVec(NTL::Vec<myT> &&a) : Vec<myT>(a) {};

  //adapters
  myVec(std::vector<std::string>& s);
  const myVec& operator=(std::initializer_list<myT> rhs);
  const myVec& operator=(std::initializer_list<usint> rhs);
  const myVec& operator=(std::initializer_list<std::string> rhs);

  inline usint size() {return this->length();};
  void SetValAtIndex(usint index, const myT&value);
  void SetValAtIndex(usint index, const char *s);
  void SetValAtIndex(usint index, const std::string& str);
  const myT& GetValAtIndex(size_t index) const;
  
  static inline myVec Single(const myZZ val) { 
    myVec vec(1);
    vec[0]=val;
    return vec;
  }


  inline myVec Add(const myVec& b) const {std::cout<<"ADD"<<std::endl; return *this+b;};
  inline myVec Sub(const myVec& b) const {std::cout<<"SUB"<<std::endl; return *this-b;};
  inline myVec Minus(const myVec& b) const {std::cout<<"MINUS"<<std::endl;return this-b;};
  inline myVec Mul(const myVec& b) const {std::cout<<"MUL"<<std::endl; return this*b;};


  inline myVec ModAdd(const myVec& b, const myZZ& modulus) const {std::cout<<"MODADD"<<std::endl; };
  inline myVec ModSub(const myVec& b, const myZZ& modulus) const {std::cout<<"MODSUB"<<std::endl; };
  inline myVec ModMul(const myVec& b, const myZZ& modulus) const {std::cout<<"MODMUL"<<std::endl; };

  // myVec& operator=(const myVec& a) : ;  


 protected:
  bool IndexCheck(usint) const;

}; //template class ends

} // namespace NTL ends

#endif // LBCRYPTO_MATH_GMPINT_GMPINTVEC_H
