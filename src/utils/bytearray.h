/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>,
 *	Kevin King <4kevinking@gmail.com>
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
 * This code provides a byte array abstraction.
 *
 */
#ifndef LBCRYPTO_UTILS_BYTEARRAY_H
#define LBCRYPTO_UTILS_BYTEARRAY_H

#include "inttypes.h"
#include <vector>
#include <array>

/**
 * @brief Type used for representing string ByteArray types.
 * Provides conversion functions to vector<uint8_t> from standard string types.
 */
struct ByteArray : public std::vector<uint8_t> {
public:
    /**
     *  @brief Standard string constructor.
     */
    ByteArray(const std::string& str);
    /**
     *  @brief C-string string constructor.
     */
    ByteArray(const char* cstr);
    /**
     *  @brief Explicit constructor for C-strings that do not end at the first null
     *  byte.
     */
    ByteArray(const char* cstr, usint len);
    /**
     *  @brief Array constructor, i.e. `ByteArray({1,2,3})`.
     */
    template<size_t N>
    ByteArray(std::array<uint8_t, N>);
    ByteArray();
    /**
     *  @brief C-string assignment.
     */
    ByteArray& operator=(const char* cstr);
    /**
     *  @brief string assignment.
     */
    ByteArray& operator= (const std::string& s);
private:
};

#endif
