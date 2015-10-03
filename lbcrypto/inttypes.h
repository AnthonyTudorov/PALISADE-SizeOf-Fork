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
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this 
 * list of conditions and the following disclaimer in the documentation and/or other 
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN 
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This code provides basic integer types for lattice crypto.
 */

#ifndef LBCRYPTO_INTTYPES_H
#define LBCRYPTO_INTTYPES_H

#include <string>
#include <stdint.h>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Type used for representing signed 8-bit integers.
 */
typedef int8_t schar;

/**
 * @brief Type used for representing signed 16-bit short integers.
 */
typedef int16_t sshort;

/**
 * @brief Type used for representing signed 32-bit integers.
 */
typedef int32_t sint;

/**
 * @brief Type used for representing unsigned 8-bit integers.
 */
typedef uint8_t uschar;

/**
 * @brief Type used for representing unsigned 16-bit short integers.
 */
typedef uint16_t usshort;

/**
 * @brief Type used for representing unsigned 32-bit integers.
 */
typedef uint32_t usint;

/**
 * @brief Type used for representing string ByteArray types.
 */
typedef std::string ByteArray;

/**
 * @brief Represents whether the polynomial ring is in EVALUATION or COEFFICIENT representation.
 */
enum Format{ EVALUATION=0, COEFFICIENT=1};


} // namespace lbcrypto ends

#endif
