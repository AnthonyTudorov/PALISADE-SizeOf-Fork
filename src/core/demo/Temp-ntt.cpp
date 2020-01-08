/*
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
#include "palisadecore.h"

using namespace lbcrypto;

void NTTBenchmark();

int main() {
	
	NTTBenchmark();

	return 0;

}

void NTTBenchmark() {

	uint32_t counter = 1000;

	usint m = 2048;
	usint phim = 1024;

	NativeInteger modulusQ("288230376151748609");
	NativeInteger rootOfUnity("64073710037604316");

	DiscreteUniformGeneratorImpl<NativeVector> dug;
	dug.SetModulus(modulusQ);
	NativeVector x = dug.GenerateVector(phim);

	// test runs to force all precomputations
	NativeVector X(m/2);

	ChineseRemainderTransformFTT<NativeVector>::PreCompute(rootOfUnity,	m, modulusQ);

	for (uint32_t i = 0; i < counter; i++)	{
		ChineseRemainderTransformFTT<NativeVector>::ForwardTransform(x, rootOfUnity, m, &X);
	}

	std::cout << "finished running NTT" << std::endl;
}

