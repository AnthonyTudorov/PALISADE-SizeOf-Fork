/*
 * @file
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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

#define PROFILE  //define this to enable PROFILELOG and TIC/TOC
// Note must be before all headers

#include <iostream>
#include "obfuscation/lweconjunctionchcprf.h"
#include "obfuscation/lweconjunctionchcprf.cpp"

#include "utils/debug.h"

using namespace lbcrypto;

int main(int argc, char* argv[]) {
	TimeVar t;

	TIC(t);
	LWEConjunctionCHCPRFAlgorithm<DCRTPoly> algorithm(1 << 15, 4, 16, 1024);
	std::cout << "Parameter Generation: " << TOC(t) << "ms" << std::endl;
	TIC(t);
	auto key = algorithm.KeyGen();
	std::cout << "Key Generation: " << TOC(t) << "ms" << std::endl;
	TIC(t);
	auto constrainedKey = algorithm.Constrain(key,  "????????????1011");
	std::cout << "Constain Key: " << TOC(t) << "ms" << std::endl;
	TIC(t);
	std::cout << algorithm.Evaluate(           key, "1011101110111011") << std::endl;
	std::cout << algorithm.Evaluate(constrainedKey, "1011101110111011") << std::endl;
	std::cout << algorithm.Evaluate(           key, "1011101110111010") << std::endl;
	std::cout << algorithm.Evaluate(constrainedKey, "1011101110111010") << std::endl;
	std::cout << "Evaluation: " << TOC(t) << "ms" << std::endl;
}
