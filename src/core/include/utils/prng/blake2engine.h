/**
 * @file blake2engine - PRNG engine based on BLAKE 2
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, Duality Technologies Inc.
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
 */
 
#ifndef _SRC_LIB_UTILS_BLAKE2ENGINE_H
#define _SRC_LIB_UTILS_BLAKE2ENGINE_H

#include <stdint.h>
#include <limits>
#include <array>
#include <stdio.h>
#include <string.h>

#include "blake2.h"

namespace lbcrypto {

class Blake2Engine {

public:
    using result_type = uint32_t;

    //Blake2Engine() : m_counter(0), m_bufferIndex(0) {};

    explicit Blake2Engine(const std::array<result_type,16> &seed): m_counter(0), m_bufferIndex(0) {
    	m_seed = seed;
    };

    static constexpr result_type min()
    	{ return std::numeric_limits<result_type>::min(); }

    static constexpr result_type max()
    	{ return std::numeric_limits<result_type>::max(); }

    result_type operator()() {

    	result_type result;

    	if (m_bufferIndex == 16)
    		m_bufferIndex = 0;

    	if (m_bufferIndex == 0)
    		Generate();

    	result = m_buffer[m_bufferIndex];

		m_bufferIndex++;

		return result;

    }

    // No copy functions.
    Blake2Engine(const Blake2Engine&) = delete;
    void operator=(const Blake2Engine&) = delete;

private:

    void Generate() {
		if (blake2b(
			m_buffer.begin(),
			m_buffer.size() * sizeof(result_type),
			&m_counter,
			sizeof(m_counter),
			m_seed.cbegin(), m_seed.size() * sizeof(result_type)) != 0)
		{
			throw std::runtime_error("PRNG: blake2xb failed");
		}
		m_counter++;
		return;
    }

    uint64_t m_counter;

    std::array<result_type,16> m_seed;

    std::array<result_type,16> m_buffer;

    uint16_t m_bufferIndex;

};

}

#endif
