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
#include "obfuscation/lwetbolinearsecret.h"

#include "utils/debug.h"

using namespace lbcrypto;

shared_ptr<vector<NativeInteger>> BuildWeightVector(const vector<uint32_t> &thresholds, PlaintextModulus p, uint32_t N, uint32_t wordSize) {

	DiscreteUniformGeneratorImpl<NativeInteger,NativeVector> dug;
	dug.SetModulus(p);

	shared_ptr<vector<NativeInteger>> weights(new vector<NativeInteger>(N));

	for (size_t k = 0; k < thresholds.size(); k++)
		for (size_t i = 0; i < wordSize-1; i++)
		{
			if (i > thresholds[k])
				(*weights)[i + k*wordSize] = dug.GenerateInteger();
			else
				(*weights)[i + k*wordSize] = 0;
		}

	return weights;

}

shared_ptr<vector<uint32_t>> BuildDataVector(const vector<uint32_t> &input, uint32_t wordSize) {

	shared_ptr<vector<uint32_t>> indices(new vector<uint32_t>(input.size()));
	for (size_t k = 0; k < input.size(); k++)
		(*indices)[k] = input[k] + k*wordSize;

	return indices;

}

int main(int argc, char* argv[]) {

	int nthreads, tid;

	// Fork a team of threads giving them their own copies of variables
	//so we can see how many threads we have to work with
#pragma omp parallel private(nthreads, tid)
	{

		/* Obtain thread number */
		tid = omp_get_thread_num();

		/* Only master thread does this */
		if (tid == 0)
		{
			nthreads = omp_get_num_threads();
			std::cout << "Number of threads = " << nthreads << std::endl;
		}
	}

	TimeVar t;

	double processingTime(0.0);

	uint32_t N = 1280;
	uint32_t n = 2048;
	uint32_t numAtt = 5;
	PlaintextModulus p = 1099511627776; //2^40
	uint32_t wordSize = 256;

	TIC(t);
	LWETBOLinearSecret algorithm(N, n, p, numAtt);
	processingTime = TOC_US(t);
	std::cout << "Parameter Generation: " << processingTime/1000 << "ms" << std::endl;

	std::cout << "\nn = " << algorithm.GetSecurityParameter() << std::endl;
	std::cout << "log2 q = " << algorithm.GetLogModulus() << std::endl;
	std::cout << "Number of attributes = " << algorithm.GetNumAtt() << std::endl;
	std::cout << "plaintext modulus = " << algorithm.GetPlaintextModulus() << std::endl;
	std::cout << "Dimension of weight/data vectors = " << algorithm.GetDimension() << std::endl;

	TIC(t);
	shared_ptr<LWETBOKeys> keys = algorithm.KeyGen();
	processingTime = TOC_US(t);
	std::cout << "\nKey generation time: " << processingTime/1000 << "ms" << std::endl;

	// vector of thresholds
	vector<uint32_t> thresholds = {134, 90, 56, 89, 200};
	shared_ptr<vector<NativeInteger>> weights = BuildWeightVector(thresholds, p, N, wordSize);

	std::cerr << "Thresholds vector: " << thresholds << std::endl;

	TIC(t);
	shared_ptr<NativeVector> ciphertext = algorithm.Obfuscate(keys,*weights);
	processingTime = TOC_US(t);
	std::cout << "\nObfuscation time: " << processingTime/1000 << "ms" << std::endl;

	vector<vector<uint32_t>> inputs = {{100, 70, 50, 80, 100},
			{200, 70, 50, 80, 100},{100, 170, 50, 80, 100},{100, 70, 60, 80, 100},
			{100, 70, 50, 92, 100},{100, 70, 50, 80, 180},
	};

	for (size_t i = 0; i < inputs.size(); i++)
	{

		shared_ptr<vector<uint32_t>> indices = BuildDataVector(inputs[i], wordSize);

		std::cout << "\nInput #" << i+1 << ": " << inputs[i] << std::endl;

		TIC(t);
		shared_ptr<NativeVector> token = algorithm.TokenGen(keys,*indices);
		processingTime = TOC_US(t);
		std::cout << "Token generation time: " << processingTime/1000 << "ms" << std::endl;

		TIC(t);
		NativeInteger result = algorithm.EvaluateClassifier(*indices,ciphertext,keys->GetPublicRandomVector(),token);
		processingTime = TOC_US(t);
		std::cout << "Evaluation time: " << processingTime/1000 << "ms" << std::endl;

		std::cout << "result (encrypted computation) = " << result << std::endl;

		TIC(t);
		NativeInteger resultClear = algorithm.EvaluateClearClassifier(*indices,*weights);
		processingTime = TOC_US(t);
		std::cout << "Evaluation time (in clear): " << processingTime/1000 << "ms" << std::endl;

		std::cout << "result (plaintext computation) = " << resultClear << std::endl;

	}

	return 0;

}
