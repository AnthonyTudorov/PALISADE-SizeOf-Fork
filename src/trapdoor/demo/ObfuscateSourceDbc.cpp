//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	6/17/2015 4:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:
	This code exercises the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.
	In this code we:
		- Generate a key pair.
		- Encrypt a string of data.
		- Decrypt the data.
		- Generate a new key pair.
		- Generate a proxy re-encryption key.
		- Re-Encrypt the encrypted data.
		- Decrypt the re-encrypted data.
	We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor and may be closer to AES-256.

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
#include "obfuscation/lweconjunctionobfuscate.h"
#include "obfuscation/lweconjunctionobfuscate.cpp"

#include "utils/debug.h"

#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;

bool NTRUPRE(bool dbg_flag, int n_evals); //defined later


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
			cout << "setting dbg_flag true" << std::endl;
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
	std::cerr  <<"Running " << argv[0] <<" with "<< n_evals << " evaluations." << std::endl;

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

	//	NTRUPRE(input, dbg_flag, n_evals);
	errorflag = NTRUPRE(dbg_flag, n_evals);

	//std::cin.get();

	return ((int)errorflag);
}

//////////////////////////////////////////////////////////////////////
//	NTRUPRE is where the core functionality is provided.
//	In this code we:
//		- Generate a key pair.
//		- Encrypt a string of data.
//		- Decrypt the data.
//		- Generate a new key pair.
//		- Generate a proxy re-encryption key.
//		- Re-Encrypt the encrypted data.
//		- Decrypt the re-encrypted data.
//////////////////////////////////////////////////////////////////////
//	We provide two different paramet settings.
//	The low-security, highly efficient settings are commented out.
//	The high-security, less efficient settings are enabled by default.
//////////////////////////////////////////////////////////////////////
//void NTRUPRE(int input, bool dbg_flag, int n_evals) {
bool NTRUPRE(bool dbg_flag, int n_evals) {

	//if dbg_flag == true; print debug outputs
	// n_evals = 1,2,3 number of evaluations to perform
	//returns
	//  errorflag = # of bad evaluations

	TimeVar t1,t_total; //for TIC TOC
	TIC(t_total); //start timer for total time

	//Set element params

	// Remove the comments on the following to use a low-security, highly efficient parameterization for integration and debugging purposes.

	usint m = 16;
	//60 bits
	BigBinaryInteger modulus("1152921504606847009");
	//27 bits
	//BigBinaryInteger modulus("67108913");
	//60 bits
	BigBinaryInteger rootOfUnity("405107564542978792");
	//27 bits
	//BigBinaryInteger rootOfUnity("61564");

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
	DiscreteFourierTransform::GetInstance().PreComputeTable(m);

	//Precomputations for DGG
	TIC(t1);
	ILVector2n::PreComputeDggSamples(dgg, ilParams);
	timeDGGSetup = TOC(t1);
	DEBUG("DGG Precomputation time: " << "\t" << timeDGGSetup << " ms");

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	std::string inputPattern = "10?";

	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);
	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	DEBUG(" \nCleartext pattern: ");
	DEBUG(clearPattern.GetPatternString());

	DEBUG(" \nCleartext pattern length: ");
	DEBUG(clearPattern.GetLength());

	std::string inputStr1 = "100";
	bool out1 = algorithm.Evaluate(clearPattern,inputStr1);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << out1);

	std::string inputStr2 = "101";
	bool out2 = algorithm.Evaluate(clearPattern,inputStr2);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr2 << " is " << out2);
	
	std::string inputStr3 = "010";
	bool out3 = algorithm.Evaluate(clearPattern,inputStr3);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr3 << " is " << out3);

	////////////////////////////////////////////////////////////
	//Generate and test the obfuscated pattern
	////////////////////////////////////////////////////////////

	bool result1 = false;
	bool result2 = false;
	bool result3 = false;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(ilParams);
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

	std::cout << "Timing Summary" << std::endl;
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

	DiscreteFourierTransform::GetInstance().Destroy();

	return (errorflag);
}


