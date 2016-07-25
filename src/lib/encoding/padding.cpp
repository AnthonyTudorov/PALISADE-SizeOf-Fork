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

#include "padding.h"

namespace lbcrypto {
    void OneZeroPad::Pad(const usint blockSize, ByteArray *byteArray) {
    	if( blockSize > byteArray->size() ) {
    		usint slotForOne = byteArray->size();
    		byteArray->resize(blockSize, 0);
    		byteArray->at(slotForOne) = 0x80;
    	}
    }

    void OneZeroPad::Unpad(ByteArray *byteArray) {
        usint nPadding = 0;
        for (sint i = byteArray->size() - 1; i >= 0; --i) {
            nPadding++;
            if (byteArray->at(i) == 0x80) {
                break;
            }
        }
        byteArray->resize(byteArray->size() - nPadding, 0);
    }

    /**
     *  @param blockSize
     *  @param byteArray
     *  Append enough 0 bytes such that the *  size of `byteArray` is
     *  `blockSize`.
     */
    void ZeroPad::Pad(const usint blockSize, ByteArray *byteArray) {
        if (blockSize > byteArray->size()) {
            byteArray->resize(blockSize, 0);
        }
    }
    /**
     *  @param byteArray
     *  Unpad `byteArray` by removing all ending 0 bytes.
     */
    void ZeroPad::Unpad(ByteArray *byteArray) {
        usint nPadding = 0;
        for (auto it = byteArray->rbegin(); it != byteArray->rend(); ++it) {
            if (*it == 0) {
                ++nPadding;
            } else {
                break;
            }
        }
        byteArray->resize(byteArray->size() - nPadding, 0);
    }

    void ZeroPad::Pad(const usint blockSize, std::vector<uint32_t> *intArray) {
        if (blockSize > intArray->size()) {
            intArray->resize(blockSize, 0);
        }
    }

    void ZeroPad::Unpad(std::vector<uint32_t> *intArray) {
        usint nPadding = 0;
        for (auto it = intArray->rbegin(); it != intArray->rend(); ++it) {
            if (*it == 0) {
                ++nPadding;
            } else {
                break;
            }
        }
        intArray->resize(intArray->size() - nPadding, 0);
    }
}
