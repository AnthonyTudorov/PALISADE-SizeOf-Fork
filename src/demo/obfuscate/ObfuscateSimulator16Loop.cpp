﻿//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	7/19/2016 4:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Dr. David Cousins
Description:
	To be added

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <iostream>
#include <fstream>
#include "../../lib/obfuscate/lweconjunctionobfuscatev2.h"
#include "../../lib/obfuscate/lweconjunctionobfuscatev2.cpp"

#include "../../lib/utils/debug.h"

#include <omp.h> //open MP header

//using namespace std;
using namespace lbcrypto;

bool CONJOBF(bool dbg_flag, int n_evals, int dataset); //defined later

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

	int n_evals = 1;

	if (argc >= 3 ) {
		if (atoi(argv[2]) < 0) {
			n_evals = 1;
		} else if (atoi(argv[2]) >= 3) {
			n_evals = 3;
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

	for (usint i = 0; i < 6; i++)
	{
		errorflag = CONJOBF(dbg_flag, n_evals, i);
	}

	return ((int)errorflag);

	//std::cin.get();
}

/**
* @brief Input parameters for conjunction obfuscation example.
*/
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
};

bool CONJOBF(bool dbg_flag, int n_evals, int dataset) {

	//if dbg_flag == true; print debug outputs
	// n_evals = 1,2,3 number of evaluations to perform
	//returns
	//  errorflag = # of bad evaluations

	TimeVar t1,t_total; //for TIC TOC
	TIC(t_total); //start timer for total time

	SecureParams const SECURE_PARAMS[] = {
		{ 16, BigBinaryInteger("288230376151711969"),
			BigBinaryInteger("110926819574788955")}, //log q = 59 bits, n = 8
			{ 32, BigBinaryInteger("4611686018427388097"),
			BigBinaryInteger("3749353375025977635") }, //log q = 64 bits, n = 16
			{ 64, BigBinaryInteger("73786976294838207169"),
			BigBinaryInteger("18478736723072519957") }, // log q = 68 bits, n = 32
			{ 128, BigBinaryInteger("1180591620717411303809"),
			BigBinaryInteger("1045241421304505831910") },  // log q = 72 bits, n = 64
			{ 256, BigBinaryInteger("18889465931478580859137"),
			BigBinaryInteger("701118114663743452021") }, // log q = 76 bits, n = 128
			{ 512, BigBinaryInteger("604462909807314587356673"),
			BigBinaryInteger("315652146132535045281800") }  // log q = 81 bits, n = 256
	};

	//Set element params

	// Remove the comments on the following to use a low-security, highly efficient parameterization for integration and debugging purposes.

	usint m = SECURE_PARAMS[dataset].m;
	BigBinaryInteger modulus(SECURE_PARAMS[dataset].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[dataset].rootOfUnity);

	usint chunkSize = 4;

	float stdDev = 4;

	//Variables for timing
	double timeDGGSetup(0.0), timeKeyGen(0.0), timeObf(0.0), timeEval1(0.0), timeEval2(0.0), timeEval3(0.0), timeTotal(0.0);


	//Prepare for parameters.
	shared_ptr<ILParams> ilParams( new ILParams(m,modulus,rootOfUnity) );

	//Set crypto parametes
	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(stdDev);			// Create the noise generator
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);

	DEBUG("Cryptosystem initialization: Performing precomputations...");

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	TIC(t1);
	ILVector2n::PreComputeDggSamples(dgg, ilParams);
	timeDGGSetup = TOC(t1);
	DEBUG("DGG Precomputation time: " << "\t" << timeDGGSetup << " ms");

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	std::string inputPattern = "1?10?10?1?10?10?";
	
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);
	LWEConjunctionObfuscationAlgorithmV2<ILVector2n> algorithm;

	DEBUG(" \nCleartext pattern: ");
	DEBUG(clearPattern.GetPatternString());

	DEBUG(" \nCleartext pattern length: ");
	DEBUG(clearPattern.GetLength());

	std::string inputStr1 = "1110010011100101";
	bool out1 = algorithm.Evaluate(clearPattern, inputStr1);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << out1);

	std::string inputStr2 = "1100110111001101";
	bool out2 = algorithm.Evaluate(clearPattern, inputStr2);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr2 << " is " << out2);

	std::string inputStr3 = "1010110110101101";
	bool out3 = algorithm.Evaluate(clearPattern, inputStr3);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr3 << " is " << out3);

	////////////////////////////////////////////////////////////
	//Generate and test the obfuscated pattern
	////////////////////////////////////////////////////////////

	bool result1 = false;
	bool result2 = false;
	bool result3 = false;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	ObfuscatedLWEConjunctionPatternV2<ILVector2n> obfuscatedPattern(ilParams,chunkSize);
	obfuscatedPattern.SetLength(clearPattern.GetLength());

	DEBUG( "Key generation started"); 
	TIC(t1);
	algorithm.KeyGen(dgg,&obfuscatedPattern);
	timeKeyGen = TOC(t1);
	DEBUG( "Key generation time: " << "\t" << timeKeyGen << " ms");

	TernaryUniformGenerator tug = TernaryUniformGenerator();	

	DEBUG( "Obfuscation Execution started");
	TIC(t1);
	algorithm.Obfuscate(clearPattern,dgg,tug,&obfuscatedPattern);
	timeObf = TOC(t1);
	DEBUG( "Obfuscation time: " << "\t" << timeObf<< " ms");

	DEBUG("Evaluation 1 started");
	TIC(t1);
	result1 = algorithm.Evaluate(obfuscatedPattern,inputStr1);
	timeEval1 = TOC(t1);
	DEBUG( " \nCleartext pattern evaluation of: " << inputStr1 << " is " << result1 << ".");
	DEBUG( "Evaluation 1 execution time: " << "\t" << timeEval1 << " ms" );

	bool errorflag = false;
	if (result1 != out1) {
		std::cout << "ERROR EVALUATING 1"<< std::endl;
		errorflag |= true;
	}

	if (n_evals > 1)  {
		DEBUG("Evaluation 2 started");
		TIC(t1);
		result2 = algorithm.Evaluate(obfuscatedPattern,inputStr2);
		timeEval2 = TOC(t1);
		DEBUG( " \nCleartext pattern evaluation of: " << inputStr2 << " is " << result2 << ".");
		DEBUG( "Evaluation 2 execution time: " << "\t" << timeEval2 << " ms" );

		if (result2 != out2) {
			std::cout << "ERROR EVALUATING 2"<< std::endl;
			errorflag |= true;
		}
	}

	if (n_evals > 2)  {
		DEBUG("Evaluation 3 started");
		TIC(t1);
		result3 = algorithm.Evaluate(obfuscatedPattern,inputStr3);
		timeEval3 = TOC(t1);
		DEBUG( "\nCleartext pattern evaluation of: " << inputStr3 << " is " << result3 << ".");
		DEBUG( "Evaluation 3 execution time: " << "\t" << timeEval3 << " ms");
		if (result3 != out3) {
			std::cout << "ERROR EVALUATING 3"<< std::endl;
			errorflag |= true;
		}
	}

	//get the total program run time.
	timeTotal = TOC(t_total);

	//print output timing results

	std::cout << "Timing Summary for n = " << m/2 << std::endl;
	std::cout << "T: DGG setup time:        " << "\t" << timeDGGSetup << " ms" << std::endl;
	std::cout << "T: Key generation time:        " << "\t" << timeKeyGen << " ms" << std::endl;
	std::cout << "T: Obfuscation execution time: " << "\t" << timeObf << " ms" << std::endl;
	std::cout << "T: Eval 1 execution time:  " << "\t" << timeEval1 << " ms" << std::endl;
	std::cout << "T: Eval 2 execution time:  " << "\t" << timeEval2 << " ms" << std::endl;
	std::cout << "T: Eval 3 execution time:  " << "\t" << timeEval3 << " ms" << std::endl;
	std::cout << "T: Total execution time:       " << "\t" << timeTotal << " ms" << std::endl;

	if (errorflag) {
		std::cout << "FAIL " << std::endl;
	} else {
		std::cout << "SUCCESS " << std::endl;
	}

	//ILVector2n::DestroyPreComputedSamples();

	return (errorflag);
}

