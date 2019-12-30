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

// #define FIXED_SEED // if defined, then uses a fixed seed number for reproducible results during debug.
// Use only one OMP thread to ensure reproducibility

namespace lbcrypto {

// Defines the PRNG implementation used by PALISADE.
// The cryptographically secure PRNG used by PALISADE is based on BLAKE2 hash functions.
// A user can replace it with a different PRNG if desired by defining the same methods as for the Blake2Engine class.
typedef Blake2Engine PRNG;

/**
* @brief The class providing the PRNG capability to all random distribution generators in PALISADE. THe security
* of Ring Learning With Errors (used for all crypto capabilities in PALISADE)
* depends on the randomness of uniform, ternary, and Gaussian distributions, which derive their randomness from the PRNG.
*/
class PseudoRandomNumberGenerator {
public:

	/**
	* @brief  Returns a reference to the PRNG engine
	*/
	static PRNG &GetPRNG () {

		// initialization of PRNGs
		if (!m_flag) {
#if defined(FIXED_SEED)
				//Only used for debugging in the single-threaded mode.
				std::cerr << "**FOR DEBUGGING ONLY!!!!  Using fixed initializer for PRNG. Use a single thread only, e.g., OMP_NUM_THREADS=1!" << std::endl;

				std::array<uint32_t,16> seed;
				seed[0] = 1;
				m_prng.reset(new PRNG(seed));

#else

				// A 256-bit seed is generated for each thread (this roughly corresponds to 128 bits of security)
				// BLAKE2 engine is used for generating the seed from current time stamp and a hash of the current thread
				// All future calls to PRNG use the seed generated here.

				std::array<uint32_t,16> initKey;
				initKey[0] = std::chrono::high_resolution_clock::now().time_since_epoch().count()+
						std::hash<std::thread::id>{}(std::this_thread::get_id());
				PRNG gen(initKey);

				std::uniform_int_distribution<uint32_t>  distribution = std::uniform_int_distribution<uint32_t>(0);
				std::array<uint32_t,16> seed;
				for (uint32_t i = 0; i < 8; i++)
					seed[i] = distribution(gen);

				m_prng.reset(new PRNG(seed));

#endif

				m_flag = true;

		}

		return *m_prng;

	}

private:

	// flag for initializing the PRNGs for each thread
	static bool 					m_flag;

	// shared pointer to a thread-specific PRNG engine
	static std::shared_ptr<PRNG> 	m_prng;

#if !defined(FIXED_SEED)
	// avoid contention on m_prng and m_flag
	// local copies of m_prng and m_prng are created for each thread
    #pragma omp threadprivate(m_prng, m_flag)
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
