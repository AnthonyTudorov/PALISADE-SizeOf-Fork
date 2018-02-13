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
#include <random>
#include "obfuscation/lweconjunctionchcprf.h"
#include "obfuscation/lweconjunctionchcprf.cpp"

#include "utils/debug.h"

using namespace lbcrypto;

string RandomBooleanString(usint length);

int main(int argc, char* argv[]) {

	int nthreads, tid;

	TimeVar t1; //for TIC TOC

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

	double processingTime(0.0), MSKeyGenTime(0.0), conKeyGenTime(0.0);

	std::string pattern ="1?1?10??????10111?1?10??????10111?1?10??";
	std::string input1 = "1011101110111011101110111011101110111011";
	std::string input2 = "1011101110111010101110111011101010111011";

	size_t len = pattern.length();

	TIC(t);
	LWEConjunctionCHCPRFAlgorithm<DCRTPoly> algorithm(1 << 20, 8, 40, 1024);
	processingTime = TOC(t);
	std::cout << "Parameter Generation: " << processingTime << "ms" << std::endl;

	std::cout << "n = " << algorithm.GetRingDimension() << std::endl;
	std::cout << "log2 q = " << algorithm.GetLogModulus() << std::endl;

	TIC(t);
	auto key = algorithm.KeyGen();
	MSKeyGenTime = TOC(t);
	std::cout << "Master Secret (Unconstrained) Key Generation: " << MSKeyGenTime << "ms" << std::endl;

	TIC(t);
	auto constrainedKey = algorithm.Constrain(key,  pattern);
	conKeyGenTime = TOC(t);
	std::cout << "Contstrained Key Generation: " << conKeyGenTime << "ms" << std::endl;

	TIC(t);
	const auto value1 = algorithm.Evaluate(           key, input1);
	const auto value3 = algorithm.Evaluate(           key, input2);
	processingTime = TOC(t);
	std::cout << "Evaluation (unconstrained): 2 * " << processingTime / 2 << "ms" << std::endl;
	TIC(t);
	const auto value2 = algorithm.Evaluate(constrainedKey, input1);
	const auto value4 = algorithm.Evaluate(constrainedKey, input2);
	processingTime = TOC(t);
	std::cout << "Evaluation (constrained): 2 * " << processingTime / 2 << "ms" << std::endl;
	//std::cout << value1 << std::endl;
	//std::cout << value2 << std::endl;
	std::cout << "pattern: " << pattern << std::endl;
	std::cout << "input 1: " << input1 << std::endl;
	std::cout << (value1 == value2 ? "Matched (Correct)" : "Did not match (Incorrect)") << std::endl;
	//std::cout << value3 << std::endl;
	//std::cout << value4 << std::endl;
	std::cout << "input 2: " << input2 << std::endl;
	std::cout << (value3 == value4 ? "Matched (Incorrect)" : "Did not match (Correct)") << std::endl;

	size_t n_evals = 100;

	vector<string> inputStr(n_evals);

    for (usint i= 0; i < n_evals; i++){
      inputStr[i] = RandomBooleanString(len);
    }

	//Variables for timing
	vector<double> timeTokenEval(n_evals);;
	vector<double> timeEval(n_evals);;

	////////////////////////////////////////////////////////////
	// test the obfuscated pattern
	////////////////////////////////////////////////////////////
	PROFILELOG("\nEvaluation started");
	for (usint i = 0; i < n_evals; i++) {

		TIC(t1);
		const auto uresult = algorithm.Evaluate(key, inputStr[i]);
		timeTokenEval[i] = TOC_US(t1);

		TIC(t1);
		const auto cresult = algorithm.Evaluate(constrainedKey, inputStr[i]);
		timeEval[i] = TOC_US(t1);

	} // end eval loop

	//print output timing results
	//note one could use PROFILELOG for these lines
	float aveTokenTime = 0.0;
	float aveTime = 0.0;
	for (usint i = 0; i < n_evals; i++){
		aveTokenTime += timeTokenEval[i];
		std::cout << "T: Token Eval "<<i<<" execution time:  " << "\t" << timeTokenEval[i]/1000 << " ms" << std::endl;
		aveTime += timeEval[i];
		std::cout << "T: Eval "<<i<<" execution time:  " << "\t" << timeEval[i]/1000 << " ms" << std::endl;
	}
	aveTime /= float(n_evals);
	aveTokenTime /= float(n_evals);

	//print output timing results
	//note one could use PROFILELOG for these lines
	std::cout << "T: MSK generation time:        " << "\t" << MSKeyGenTime << " ms" << std::endl;
	std::cout << "T: Obfuscation execution time: " << "\t" << conKeyGenTime << " ms" << std::endl;
	std::cout << "T: Average token evaluation time:  " << "\t" << aveTokenTime/1000 << " ms" << std::endl;
	std::cout << "T: Average evaluation time:  " << "\t" << aveTime/1000 << " ms" << std::endl;
	std::cout << "T: Average total evaluation time:       " << "\t" << aveTokenTime/1000 + aveTime/1000 << " ms" << std::endl;

}

string RandomBooleanString(usint length) {
  static std::default_random_engine         e{};
  static std::uniform_int_distribution<int> d{0, 1};

  string str("");
  for (usint i=0; i<length; i++){
    str+= to_string(d(e));
  }

  return str;
}
