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
// Note must must be before all headers

#include <iostream>
#include <fstream>
#include <random>
#include "obfuscation/lweconjunctionobfuscate.h"
#include "utils/debug.h"

using namespace lbcrypto;

bool CONJOBF(bool dbg_flag, size_t n_evals, int  n); //defined later

string RandomBooleanString(usint length);

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
	bool errorflag = false;

	if (argc < 2) { // called with no arguments
		std::cout << "arg 1 = debugflag 0:1 [0] " << std::endl;
		std::cout << "arg 2 = num evals 1:3 [1] " << std::endl;
	}
	bool dbg_flag = false; 

	if (argc >= 2 ) {
		if (atoi(argv[1]) != 0) {
#ifndef NDEBUG
			dbg_flag = true;
			std::cout << "setting dbg_flag true" << std::endl;
#endif
		}
	}

	std::cerr  <<"Running " << argv[0] <<" with "<< omp_get_num_procs() << " processors." << std::endl;

	size_t n_evals = 1;

	if (argc >= 3 ) {
		if (atoi(argv[2]) < 0) {
			n_evals = 1;
		} else {
			n_evals = atoi(argv[2]);
		}
	}
	std::cerr << "Running " << argv[0] << " with " << n_evals << " evaluations." << std::endl;

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

	for (usint n = 1<<9; n < 1<<10; n=2*n)
	{
		errorflag = CONJOBF(dbg_flag, n_evals, n);
		if (errorflag)
			return ((int)errorflag);
	}

	return ((int)errorflag);

	//std::cin.get();
}


//////////////////////////////////////////////////////////////////////
bool CONJOBF(bool dbg_flag, size_t n_evals, int n) {

	//if dbg_flag == true; print debug outputs
	// n_evals = 1,2,3 number of evaluations to perform
	//returns
	//  errorflag = # of bad evaluations


	DEBUG("DEBUG IS TRUE");
	PROFILELOG("PROFILELOG IS TRUE");
#ifdef PROFILE
	std::cout << "PROFILE is defined" << std::endl;
#endif
#ifdef NDEBUG
	std::cout << "NDEBUG is defined" << std::endl;
#endif

	TimeVar t1, t_total; //for TIC TOC
	TIC(t_total); //start timer for total time

	usint m = 2*n;

	usint chunkSize = 8;
	usint base = 1<<20;

	//if (n > 1<<11)
	//	base = 1<<18;

	//Generate the test pattern
	std::string inputPattern = "1?10?10?1?10?10?1?10?10?1?10??0?1?10?10?";;
	ClearLWEConjunctionPattern<DCRTPoly> clearPattern(inputPattern);

	ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern;
	obfuscatedPattern.SetChunkSize(chunkSize);
	obfuscatedPattern.SetBase(base);
	obfuscatedPattern.SetLength(clearPattern.GetLength());
	obfuscatedPattern.SetRootHermiteFactor(1.006);

	LWEConjunctionObfuscationAlgorithm<DCRTPoly> algorithm;

	//Variables for timing
	double timeKeyGen(0.0), timeObf(0.0);

	double stdDev = SIGMA;
	DCRTPoly::DggType dgg(stdDev);			// Create the noise generator

																				//Finds q using the correctness constraint for the given value of n
	algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);

	//this code finds the values of q and n corresponding to the root Hermite factor in obfuscatedPattern
	//algorithm.ParamsGen(dgg, &obfuscatedPattern);

	const shared_ptr<typename DCRTPoly::Params> ilParams = obfuscatedPattern.GetParameters();

	const BigInteger &modulus = ilParams->GetModulus();
	const BigInteger &rootOfUnity = ilParams->GetRootOfUnity();
	m = ilParams->GetCyclotomicOrder();

	PROFILELOG("\nq = " << modulus);
	PROFILELOG("rootOfUnity = " << rootOfUnity);
	PROFILELOG("n = " << m / 2);
	PROFILELOG(printf("delta=%lf", obfuscatedPattern.GetRootHermiteFactor()));
	PROFILELOG("\nbase = " << base);

	typename DCRTPoly::DugType dug;
	typename DCRTPoly::TugType tug;

	PROFILELOG("\nCryptosystem initialization: Performing precomputations...");

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	DiscreteFourierTransform::PreComputeTable(m);

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	PROFILELOG("Key generation started");
	TIC(t1);
	algorithm.KeyGen(dgg, &obfuscatedPattern);
	timeKeyGen = TOC(t1);
	PROFILELOG("Key generation time: " << "\t" << timeKeyGen << " ms");

	BinaryUniformGenerator dbg = BinaryUniformGenerator();

	DEBUG("Obfuscation Execution started");
	TIC(t1);
	algorithm.Obfuscate(clearPattern, dgg, tug, &obfuscatedPattern);
	timeObf = TOC(t1);
	PROFILELOG("Obfuscation time: " << "\t" << timeObf << " ms");

	vector<string> inputStr(n_evals);

    for (usint i= 0; i < n_evals; i++){
      inputStr[i] = RandomBooleanString(clearPattern.GetLength());
    }

    vector<bool> out(n_evals);
    vector<bool> result(n_evals);
	bool errorflag = false;

	//Variables for timing
	vector<double> timeEval(n_evals);;

	double timeTotal(0.0);

	size_t counter = 0;

	// run one evaluation before starting the benchmarking
	algorithm.Evaluate(obfuscatedPattern, RandomBooleanString(clearPattern.GetLength()));

	////////////////////////////////////////////////////////////
	// test the obfuscated pattern
	////////////////////////////////////////////////////////////
	PROFILELOG("\nEvaluation started");
	for (usint i = 0; i < n_evals; i++) {
		out[i] = algorithm.Evaluate(clearPattern, inputStr[i]);
		DEBUG(" \nCleartext pattern evaluation of: " << inputStr[i] << " is " << out[i]);

		if (out[i])
			counter++;

		TIC(t1);
		result[i] = algorithm.Evaluate(obfuscatedPattern, inputStr[i]);
		timeEval[i] = TOC_US(t1);

		DEBUG(" \nObfuscated pattern evaluation of: " << inputStr[i] << " is " << result[i] << ".");
		//PROFILELOG("Evaluation "<<i<<" execution time: " << "\t" << timeEval[i] << " ms");

		if (result[i] != out[i]) {
		  std::cout << "ERROR EVALUATING "<<i<<" got "<<result[i]<<" wanted "<<out[i]<< std::endl;
		  errorflag |= true;
		}
	} // end eval loop
	//get the total program run time.
	timeTotal = TOC(t_total);

	//print output timing results
	//note one could use PROFILELOG for these lines
	std::cout << "Timing Summary for n = " << m / 2 << std::endl;
	float aveTime = 0.0;
	for (usint i = 0; i < n_evals; i++){
		aveTime += timeEval[i];
		std::cout << "T: Eval "<<i<<" execution time:  " << "\t" << timeEval[i]/1000 << " ms" << std::endl;
	}
	aveTime /= float(n_evals);

	if (errorflag) {
		std::cout << "FAIL " << std::endl;
	}
	else {
		std::cout << "SUCCESS " << std::endl;
	}


	//print output timing results
	//note one could use PROFILELOG for these lines
	std::cout << "\nTiming Summary for n = " << m / 2 << std::endl;
	std::cout << "T: Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
	std::cout << "T: Obfuscation execution time: " << "\t" << timeObf << " ms" << std::endl;
	std::cout << "T: Average evaluation execution time:  " << "\t" << aveTime/1000 << " ms" << std::endl;
	std::cout << "T: Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

	DiscreteFourierTransform::Reset();

	return (errorflag);
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
