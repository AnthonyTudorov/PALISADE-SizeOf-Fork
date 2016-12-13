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

class myZZ : public NTL::ZZ {

public:

  myZZ();
  myZZ(long a);
  myZZ(INIT_SIZE_TYPE, long k);
  myZZ(std::string s);
  myZZ(NTL::ZZ &a);
  myZZ(const NTL::ZZ &a);

  myZZ(NTL::ZZ &&a);

//  myZZ& operator=(const myZZ &rhs);


  //myZZ( ZZ && zzin) : ZZ(zzin), m_MSB(5){};

  //  void InitMyZZ(ZZ &&zzin) const {this->m_MSB = 1; return;}
  void SetMSB();
  usint GetMSB() const;

  //adapter kit
  static const myZZ& zero();


private:
  size_t m_MSB;
    //inline static usint GetMSBLimb_t(ZZ_limb_t x);
    usint GetMSBLimb_t( ZZ_limb_t x);
}; //class ends
  
}//namespace ends

#endif //LBCRYPTO_MATH_GMPINT_GMPINT_H


