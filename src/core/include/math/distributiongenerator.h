/**
 * @file distributiongenerator.h This code provides basic structure for distribution generators. This should be inherited by all other distribution generators.
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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

#ifndef LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_

#include <chrono>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include "backend.h"
#include "utils/prng/blake2engine.h"

//#define FIXED_SEED // if defined, then uses a fixed seed number for reproducible results during debug. Use only one OMP thread to ensure reproducibility

namespace lbcrypto {

// Replace with a different PRNG if desired
typedef Blake2Engine PRNG;

class PseudoRandomNumberGenerator {
public:
	static PRNG &GetPRNG () {

		// initialization of PRNGs
		if (!m_flag) {
#if defined(FIXED_SEED)
				//Only used for debugging in the single-threaded mode.
				std::cerr << "**FOR DEBUGGING ONLY!!!!  Using fixed initializer for PRNG. Use a single thread only!" << std::endl;

				std::mt19937 *gen;
				std::array<uint32_t,16> seed;
				seed[0] = 1;
				m_prng.reset(new PRNG(seed));

				m_flag = true;
#else
#pragma omp critical
			{
				m_flag = true;
			}
#pragma omp parallel
			{
				// A 512-bit seed is generated for each thread
				// Mersenne-Twister engine is used only for generating the seed
				// All calls to PRNG use the BLAKE 2 protocol (cryptographically secure PRNG)
				std::mt19937 gen = std::mt19937(std::chrono::high_resolution_clock::now().time_since_epoch().count()+
						std::hash<std::thread::id>{}(std::this_thread::get_id()));
				std::uniform_int_distribution<uint32_t>  distribution = std::uniform_int_distribution<uint32_t>(0);
				std::array<uint32_t,16> seed;
				for (uint32_t i = 0; i < 16; i++)
					seed[i] = distribution(gen);

				m_prng.reset(new PRNG(seed));

			}
#endif
		}

		return *m_prng;

	}

private:

	// flag for initializing the PRNGs for each thread
	static bool 					m_flag;

	static std::shared_ptr<PRNG> 	m_prng;
#if !defined(FIXED_SEED)
	// avoid contention on m_prng 
    #pragma omp threadprivate(m_prng)
#endif
};

/**
* @brief Abstract class describing generator requirements.
*
* The Distribution Generator defines the methods that must be implemented by a real generator.
* It also holds the single PRNG, which should be called by all child class when generating a random number is required.
*
*/
template<typename VecType>
class DistributionGenerator {
public:
	DistributionGenerator () {}
	virtual ~DistributionGenerator() {}
};

} // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
