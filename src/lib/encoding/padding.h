/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Kevin King <4kevinking@gmail.com>
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
 * This code provides padding of plaintext messages.
 */

#ifndef LBCRYPTO_ENCODING_PADDING_H
#define LBCRYPTO_ENCODING_PADDING_H
#include "../utils/bytearray.h"
#include "../utils/inttypes.h"

namespace lbcrypto {
    /**
     *  A Scheme to add and remove padding froma ByteArray so that the size of
     *  the ByteArray is 0 mod `blockSize`.
     */
    class PaddingScheme {
    public:
        /**
         *  @param blockSize
         *  @param byteArray
         *  Pads `byteArray` to size 0 mod `blockSize`.
         */
        static void Pad(const usint blockSize, ByteArray *byteArray);
        /**
         *  @param byteArray
         *  Unpads `byteArray` to the original contents before padding.
         *  Independent of block size.
         */
        static void Unpad(ByteArray *byteArray);
        /**
         *  @param blockSize
         *  @param intArray
         *  Pads `intArray` to size 0 mod `blockSize`.
         */
        static void Pad(const usint blockSize, std::vector<uint32_t> *intArray);
        /**
         *  @param intArray
         *  Unpads `intArray` to the original contents before padding.
         *  Independent of block size.
         */
        static void Unpad(std::vector<uint32_t> *intArray);
    };

    /**
     *  A PaddingScheme which appends a '\\x80' byte followed by enough '\\0'
     *  bytes to fill the remainder of the block.
     */
    //class OneZeroPad : public PaddingScheme {
    //public:
    //    /**
    //     *  @param blockSize
    //     *  @param byteArray
    //     *  Appends a '\\x80' byte followed by enough '\\0' bytes such that the
    //     *  size of `byteArray` is 0 mod `blockSize`.
    //     */
    //    static void Pad(const usint blockSize, ByteArray *byteArray);
    //    /**
    //     *  @param byteArray
    //     *  Unpada `byteArray` by removing the last '\\x80' byte and all
    //     *  following '\\0' bytes.
    //     */
    //    static void Unpad(ByteArray *byteArray);
    //    /**
    //     *  @param blockSize
    //     *  @param byteArray
    //     *  Appends a '\\x80' byte followed by enough '\\0' bytes such that the
    //     *  size of `byteArray` is 0 mod `blockSize`.
    //     */
    //    static void Pad(const usint blockSize, ByteArray *byteArray);
    //    /**
    //     *  @param byteArray
    //     *  Unpada `byteArray` by removing the last '\\x80' byte and all
    //     *  following '\\0' bytes.
    //     */
    //    static void Unpad(ByteArray *byteArray);
    //};

    /**
     *  Padding for a single block, only appends 0 bytes to preserve homomorphic
     *  operations.
     */
    class ZeroPad : public PaddingScheme {
    public:
        /**
         *  @param blockSize
         *  @param byteArray
         *  Append enough 0 bytes such that the *  size of `byteArray` is
         *  `blockSize`.
         */
        static void Pad(const usint blockSize, ByteArray *byteArray);
        /**
         *  @param byteArray
         *  Unpad `byteArray` by removing all ending 0 bytes.
         */
        static void Unpad(ByteArray *byteArray);
        /**
         *  @param blockSize
         *  @param intArray
         *  Append enough 0 bytes such that the *  size of `intArray` is
         *  `blockSize`.
         */
        static void Pad(const usint blockSize, std::vector<uint32_t> *intArray);
        /**
         *  @param intArray
         *  Unpad `intArray` by removing all ending 0 bytes.
         */
        static void Unpad(std::vector<uint32_t> *intArray);

    };
}

#endif // LBCRYPTO_ENCODING_PADDING_H