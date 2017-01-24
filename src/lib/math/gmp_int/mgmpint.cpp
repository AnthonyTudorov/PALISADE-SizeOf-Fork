//LAYER 1 : PRIMITIVE DATA STRUCTURES AND OPERATIONS
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
 *
 * This file contains the C++ code for implementing the main class for
 * big integers: ubint. Big integers are represented as arrays of
 * native usigned integers. The native integer type is supplied as a
 * template parameter.  Currently implementation based on uint32_t is
 * supported. One needs a native integer 2x the size of the chosen type for
 * certain math operations.
 */

#define _SECURE_SCL 0 // to speed up VS


#include <iostream>
#include <fstream>
#include <sstream>
#include "gmpint.h"
#include "mgmpint.h"

namespace NTL {

  const myZZ_p myZZ_p::ZERO=myZZ_p(0L);
  const myZZ_p myZZ_p::ONE=myZZ_p(1);
  const myZZ_p myZZ_p::TWO=myZZ_p(2);
  const myZZ_p myZZ_p::THREE=myZZ_p(3);
  const myZZ_p myZZ_p::FOUR=myZZ_p(4);
  const myZZ_p myZZ_p::FIVE=myZZ_p(5);

  myZZ_p::myZZ_p():ZZ_p() {}
  myZZ_p::myZZ_p(int a): ZZ_p(a) {}
  myZZ_p::myZZ_p(long a): ZZ_p(a) {}
  myZZ_p::myZZ_p(unsigned long a): ZZ_p(a) {}
  myZZ_p::myZZ_p(const unsigned int &a): ZZ_p(a) {}
  myZZ_p::myZZ_p(unsigned int &a): ZZ_p(a) {}
myZZ_p::myZZ_p(INIT_SIZE_TYPE, long k): ZZ_p(INIT_SIZE, k) {m_MSB=0; } //??
  myZZ_p::myZZ_p(std::string s): ZZ_p(conv<ZZ_p>(s.c_str())) {}
  myZZ_p::myZZ_p(const char *s): ZZ_p(conv<ZZ_p>(s)) {}

myZZ_p::myZZ_p(NTL::ZZ &a): ZZ_p(a) {} //??
myZZ_p::myZZ_p(const NTL::ZZ &a): ZZ_p(a) {}  //??
myZZ_p::myZZ_p(NTL::ZZ &&a) : ZZ_p(a) {}  //??

  myZZ_p::myZZ_p(NTL::ZZ_p &a): ZZ_p(a) {}
  myZZ_p::myZZ_p(const NTL::ZZ_p &a): ZZ_p(a) {}
  myZZ_p::myZZ_p(NTL::ZZ_p &&a) : ZZ_p(a) {}

//  myZZ_p& myZZ_p::operator=(const myZZ_p& rhs) {
//
//  }

  usint myZZ_p::GetMSB() {
    this->SetMSB(); //note no one needs to SetMSB()
    return m_MSB;
  }


  void myZZ_p::SetMSB()
  {

    size_t sz = this->size();
    //std::cout<<"size "<<sz <<" ";
    if (sz==0) { //special case for empty data
      m_MSB = 0;
      return;
    }

    m_MSB = (sz-1) * NTL_ZZ_p_NBITS; //figure out bit location of all but last limb
    //std::cout<<"msb starts with "<<m_MSB<< " ";
    //could also try
    //m_MSB = NumBytes(*this)*8;
    const ZZ_p_limb_t *zlp = ZZ_p_limbs_get(*this);
    //for (usint i = 0; i < sz; i++){
    //std::cout<< "limb["<<i<<"] = "<<zlp[i]<<std::endl;
    //}

    usint tmp = GetMSBLimb_t(zlp[sz-1]); //add the value of that last limb.
    //std::cout<< "tmp = "<<tmp<<std::endl;
    m_MSB+=tmp;
    //std::cout<<"msb ends with "<<m_MSB<< " " <<std::endl;
  }

 // inline static usint GetMSBLimb_t(ZZ_p_limb_t x){
  usint myZZ_p::GetMSBLimb_t( ZZ_p_limb_t x){
    const usint bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    uint64_t r = 0;
    if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
    if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
    return r + bval[x];
  }

  void myZZp::m_setOTM(const myZZ &q) 
  {
    //should test first but for now just set
    m_OTM = q;
    m_OTM_state = INITIALIZED;
  }
  bool myZZp::m_checkOTM(const myZZ &q) const {
    if (m_OTM_state == GARBAGE){
      throw std::logic_error("myZZp::function() called with uninitialized OTM");
    }
    return (m_OTM == q);
  }
  myZZ& myZZp::m_getOTM(void) const;
    if (m_OTM_state == GARBAGE){
      throw std::logic_error("myZZp::checkfunction() called with uninitialized OTM");
    } else {
      return m_OTM;
    }
  }



  //adapter kit
  const myZZ_p& myZZ_p::zero() {return (ZZ_p::zero());}

  //palisade conversion methods
  usint myZZ_p::ConvertToUsint() const{ return (conv<usint>(*this)); }
  usint myZZ_p::ConvertToInt() const{ return (conv<int>(*this)); }
  uint32_t myZZ_p::ConvertToUint32() const { return (conv<uint32_t>(*this));}

  uint64_t myZZ_p::ConvertToUint64() const{ return (conv<uint64_t>(*this));}
  float myZZ_p::ConvertToFloat() const{ return (conv<float>(*this));}
  double myZZ_p::ConvertToDouble() const{ return (conv<double>(*this));}
  long double myZZ_p::ConvertToLongDouble() const {
    std::cerr<<"can't convert to long double"<<std::endl; 
    return 0.0L;
  }
  
  const std::string myZZ_p::ToString() const
  {
    //todo Not sure if this string is safe, it may be ephemeral if not returned  by value.
    std::stringstream result("");
    result << *this;
    return result.str();
  }	


} // namespace NTL ends

