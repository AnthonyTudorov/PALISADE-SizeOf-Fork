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
#include "gmpint.h"

namespace NTL {
  myZZ::myZZ():ZZ() {}
  myZZ::myZZ(long a): ZZ(a) {}
  myZZ::myZZ(INIT_SIZE_TYPE, long k): ZZ(INIT_SIZE, k) {m_MSB=0; }
  myZZ::myZZ(std::string s): ZZ() {std::cout<<"STRINGCTR"<<std::endl; }
  myZZ::myZZ(NTL::ZZ &a): ZZ(a) {}
  myZZ::myZZ(const NTL::ZZ &a): ZZ(a) {}
  myZZ::myZZ(NTL::ZZ &&a) : ZZ(a) {}

//  myZZ& myZZ::operator=(const myZZ& rhs) {
//
//  }

  usint myZZ::GetMSB() const {
    return m_MSB;
  }

  void myZZ::SetMSB()
  {
    m_MSB = 0;
    size_t sz = this->size();

    m_MSB = (sz-1) * NTL_ZZ_NBITS; //figure out bit location of all but last limb
    //could also try
    //m_MSB = NumBytes(*this)*8;
     const ZZ_limb_t *zlp = ZZ_limbs_get(*this);
    
    m_MSB+= GetMSBLimb_t(zlp[sz]); //add the value of that last limb.
  }

 // inline static usint GetMSBLimb_t(ZZ_limb_t x){
  usint myZZ::GetMSBLimb_t( ZZ_limb_t x){
    const usint bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    uint64_t r = 0;
    if (x & 0xFFFFFFFF00000000) { r += 32/1; x >>= 32/1; }
    if (x & 0x00000000FFFF0000) { r += 32/2; x >>= 32/2; }
    if (x & 0x000000000000FF00) { r += 32/4; x >>= 32/4; }
    if (x & 0x00000000000000F0) { r += 32/8; x >>= 32/8; }
    return r + bval[x];
  }

  //adapter kit
  const myZZ& myZZ::zero() {return myZZ(ZZ::zero());}

} // namespace NTL ends
