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
 * implementation based on uint32_t and uint64_t is
 * supported. a native double the base integer size is also needed.
  */

#ifndef LBCRYPTO_MATH_GMPINT_GMPINT_H
#define LBCRYPTO_MATH_GMPINT_GMPINT_H



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

#include "time.h"
#include <chrono>
#include "../../utils/debug.h"

#include <NTL/ZZ.h>
#include <NTL/ZZ_limbs.h>


/**
 *@namespace NTL
 * The namespace of this code
 */
namespace NTL{

  //todo: the following will be deprecated
  const usint BARRETT_LEVELS = 8;	


class myZZ : public NTL::ZZ {

public:

  myZZ();
  myZZ(int a);
  myZZ(long a);
  myZZ(unsigned long a);
  myZZ(const unsigned int &a);
  myZZ(unsigned int &a);
  myZZ(INIT_SIZE_TYPE, long k);
  myZZ(std::string s);
  myZZ(const char * s);
  myZZ(NTL::ZZ &a);
  myZZ(const NTL::ZZ &a);

  myZZ(NTL::ZZ &&a);



//  myZZ& operator=(const myZZ &rhs);
  //myZZ( ZZ && zzin) : ZZ(zzin), m_MSB(5){};

  static const myZZ ZERO;
  static const myZZ ONE;
  static const myZZ TWO;
  static const myZZ THREE;
  static const myZZ FOUR;
  static const myZZ FIVE;


  //  void InitMyZZ(ZZ &&zzin) const {this->m_MSB = 1; return;}
  //adapter kit
  usint GetMSB();
  static const myZZ& zero();

  //palisade conversion methods 
  usint ConvertToUsint() const;
  usint ConvertToInt() const;
  uint32_t ConvertToUint32() const;
  uint64_t ConvertToUint64() const;
  float ConvertToFloat() const;
  double ConvertToDouble() const;
  long double ConvertToLongDouble() const;

  //stopped here: it has problems finding which clear to use

  //read  http://www.prenhall.com/divisions/esm/app/kafura/secure/chapter7/html/7.5_inheritance.htm
  //and see if we can figure out what happened.

  //inline void clear(myZZ& a) { clear(*this);}; //why can't I inherit this?
  //inline void clear(myZZ& a) { clear(a);}; //this compiled but calls ZZ:clear in perpetual loop. 
  
  //comparison method inline for speed
  inline sint Compare(const myZZ& a) const {return compare(*this,a); };



  //palisade arithmetic methods all inline for speed
  inline myZZ Add(const myZZ& b) const {return *this+b;};
  inline myZZ Plus(const myZZ& b) const {return *this+b;}; //to be deprecated

  inline myZZ Sub(const myZZ& b) const  {return((*this<b)? ZZ(0):( *this-b));};  
  inline myZZ Minus(const myZZ& b) const  {return((*this<b)? ZZ(0):( *this-b));}; //to be deprecated
  inline myZZ operator-(const myZZ &b) const {
    if (*this < b) { // should return 0
      return ZZ(0);
    }
    myZZ tmp;
    sub(tmp, *this, b);
    return tmp ;
  };
  inline myZZ& operator -=(const myZZ &a) {
    if (*this<a) { // note b>a should return 0
      *this = ZZ(0);
      return *this;
    }
    *this = *this-a;
    return *this;
  };// note this<a should return 0
  
  inline myZZ Mul(const myZZ& b) const {return *this*b;};
  inline myZZ Times(const myZZ& b) const {return *this*b;}; //to be deprecated
  inline myZZ Div(const myZZ& b) const {return *this/b;};
  inline myZZ DividedBy(const myZZ& b) const {return *this/b;};
  inline myZZ Exp(const usint p) const {return power(*this,p);};

  //palisade modular arithmetic methods all inline for speed
  inline myZZ Mod(const myZZ& modulus) const {return *this%modulus;};
  inline myZZ ModBarrett(const myZZ& modulus, const myZZ& mu) const {return *this%modulus;};
inline    myZZ ModBarrett(const myZZ& modulus, const myZZ mu_arr[BARRETT_LEVELS+1]) const  {return *this%modulus;};
   inline myZZ ModInverse(const myZZ& modulus) const {return InvMod(*this%modulus, modulus);};
   inline myZZ ModAdd(const myZZ& b, const myZZ& modulus) const {return AddMod(*this%modulus, b%modulus, modulus);};
   inline myZZ ModSub(const myZZ& b, const myZZ& modulus) const
  {
    ZZ newthis(*this%modulus);
    ZZ newb(b%modulus);
    //if (newthis<newb){
    //  return ZZ(0);
    //}
    return SubMod(newthis, newb, modulus);      
  };

   inline myZZ ModMul(const myZZ& b, const myZZ& modulus) const {return MulMod(*this%modulus, b%modulus, modulus);};
   inline myZZ ModBarrettMul(const myZZ& b, const myZZ& modulus,const myZZ& mu) const {return MulMod(*this%modulus, b%modulus, modulus);};
   inline myZZ ModBarrettMul(const myZZ& b, const myZZ& modulus,const myZZ mu_arr[BARRETT_LEVELS]) const  {return MulMod(*this%modulus, b%modulus, modulus);};
   inline myZZ ModExp(const myZZ& b, const myZZ& modulus) const {return PowerMod(*this%modulus, b%modulus, modulus);};

  //palisade string conversion
  const std::string ToString() const;	
  
  
    inline long operator==(const myZZ& b) const
    { return this->Compare(b) == 0; }

private:
    //adapter kits
  void SetMSB();

  size_t m_MSB;

  usint GetMSBLimb_t( ZZ_limb_t x);
}; //class ends
  
}//namespace ends

#endif //LBCRYPTO_MATH_GMPINT_GMPINT_H


