//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.03
Last Edited:
	12/22/2016
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Dr. David Cousins, dcousins@bbn.com

Description:
 
This is a highly simplified version of ObfuscateSimulator.cpp used for debugging.
License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#define PROFILE  //define this to enable PROFILELOG and TIC/TOC 
                  // Note must must be before all headers

#include <iostream>
#include <fstream>
#include "../../lib/obfuscate/lweconjunctionobfuscatev3.h"
#include "../../lib/obfuscate/lweconjunctionobfuscatev3.cpp"


#include "../../lib/utils/debug.h"

#include <omp.h> //open MP header

//using namespace std;
using namespace lbcrypto;

bool CONJOBF(bool dbg_flag, int n_evals); //defined later


//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){
	bool errorflag = false;

	if (argc < 2) { // called with no arguments
		std::cout << "Usage is `"<<argv[0]<<" arg1 arg2 arg3' where: " << std::endl;
		std::cout << "  arg1 indicate verbosity of output. Possible values are 0 or 1 with 1 being verbose.  Default is 0." << std::endl;
		std::cout << "  arg2 indicates number of evaluation operations to run.  Possible values are 1, 2 or 3.  Default is 1." << std::endl;
		std::cout << "If no input is given, then this message is displayed, defaults are assumed and user is prompted for ring dimension." << std::endl;
	}
	bool dbg_flag = false; 

	if (argc >= 2 ) {
		if (atoi(argv[1]) != 0) {
#if !defined(NDEBUG)
			dbg_flag = true;
			// std::cout << "setting dbg_flag true" << std::endl;
#endif
		}
	}

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

	std::cerr  <<"Configured to run " << argv[0] <<" with "<< omp_get_num_procs() << " processor[s] and " << n_evals << " evaluation[s]." << std::endl;

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

	errorflag = CONJOBF(dbg_flag, n_evals);

	//system("PAUSE");

	return ((int)errorflag);

}

//////////////////////////////////////////////////////////////////////
bool CONJOBF(bool dbg_flag, int n_evals) {

	//if dbg_flag == true; print debug outputs
	// n_evals = 1,2,3 number of evaluations to perform
	//returns
	//  errorflag = # of bad evaluations


  DEBUG("DEBUG IS TRUE");
  PROFILELOG("PROFILELOG IS TRUE");
#ifdef PROFILE
  std::cout<<"PROFILE is defined"<<std::endl;
#endif
#ifdef NDEBUG
  std::cout<<"NDEBUG is defined"<<std::endl;
#endif

	TimeVar t1,t_total; //for TIC TOC
	TIC(t_total); //start timer for total time

	usint m = 16;
	//54 bits
	//BigBinaryInteger modulus("9007199254741169");
	//BigBinaryInteger rootOfUnity("7629104920968175");

	usint chunkSize = 2;

	//Generate the test pattern
	std::string inputPattern = "1?10?1";
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);

	ObfuscatedLWEConjunctionPatternV3<ILVector2n> obfuscatedPattern;
	obfuscatedPattern.SetChunkSize(chunkSize);
	obfuscatedPattern.SetLength(clearPattern.GetLength());
	obfuscatedPattern.SetRootHermiteFactor(1.006);

	LWEConjunctionObfuscationAlgorithmV3<ILVector2n> algorithm;

	//Variables for timing
	double timeDGGSetup(0.0), timeKeyGen(0.0), timeObf(0.0), timeEval1(0.0), 
		timeEval2(0.0), timeEval3(0.0), timeTotal(0.0);

	double stdDev = SIGMA;
	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(stdDev);			// Create the noise generator

	//Finds q using the correctness constraint for the given value of n
	algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);

	//this code finds the values of q and n corresponding to the root Hermite factor in obfuscatedPattern
	//algorithm.ParamsGen(dgg, &obfuscatedPattern);

	const shared_ptr<ILParams> ilParams = std::dynamic_pointer_cast<ILParams>(obfuscatedPattern.GetParameters());

	const BigBinaryInteger &modulus = ilParams->GetModulus();
	const BigBinaryInteger &rootOfUnity = ilParams->GetRootOfUnity();
	m = ilParams->GetCyclotomicOrder();

	PROFILELOG( "\nq = " << modulus);
	PROFILELOG("rootOfUnity = " << rootOfUnity);
	PROFILELOG("n = " << m / 2 );
	PROFILELOG(printf("delta=%lf", obfuscatedPattern.GetRootHermiteFactor()));

	//Set crypto parametes
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);
	TernaryUniformGenerator tug = TernaryUniformGenerator();			// Create the noise generator

	PROFILELOG("\nCryptosystem initialization: Performing precomputations...");

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	TIC(t1);
	ILVector2n::PreComputeDggSamples(dgg, ilParams);
	timeDGGSetup = TOC(t1);
	PROFILELOG("DGG Precomputation time: " << "\t" << timeDGGSetup << " ms");

	////////////////////////////////////////////////////////////
	//Test the cleartext pattern
	////////////////////////////////////////////////////////////

	DEBUG(" \nCleartext pattern: ");
	DEBUG(clearPattern.GetPatternString());

	DEBUG(" \nCleartext pattern length: ");
	DEBUG(clearPattern.GetLength());

	std::string inputStr1 = "111001";
	bool out1 = algorithm.Evaluate(clearPattern,inputStr1);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr1 << " is " << out1);

	std::string inputStr2 = "110011";
	bool out2 = algorithm.Evaluate(clearPattern,inputStr2);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr2 << " is " << out2);
	
	std::string inputStr3 = "101011";
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

	PROFILELOG( "Key generation started");
	TIC(t1);
	algorithm.KeyGen(dgg,&obfuscatedPattern);
	timeKeyGen = TOC(t1);
	PROFILELOG( "Key generation time: " << "\t" << timeKeyGen << " ms");

	BinaryUniformGenerator dbg = BinaryUniformGenerator();	

	DEBUG( "Obfuscation Execution started");
	TIC(t1);
	algorithm.Obfuscate(clearPattern,dgg,tug,&obfuscatedPattern);
	timeObf = TOC(t1);
	PROFILELOG( "Obfuscation time: " << "\t" << timeObf<< " ms");

	PROFILELOG("Evaluation 1 started");
	TIC(t1);
	result1 = algorithm.Evaluate(obfuscatedPattern,inputStr1);
	timeEval1 = TOC(t1);
	DEBUG( " \nCleartext pattern evaluation of: " << inputStr1 << " is " << result1 << ".");
	PROFILELOG( "Evaluation 1 execution time: " << "\t" << timeEval1 << " ms" );

	bool errorflag = false;
	if (result1 != out1) {
		std::cout << "ERROR EVALUATING 1"<< std::endl;
		errorflag |= true;
	}

	if (n_evals > 1)  {
		PROFILELOG("Evaluation 2 started");
		TIC(t1);
		result2 = algorithm.Evaluate(obfuscatedPattern,inputStr2);
		timeEval2 = TOC(t1);
		DEBUG( " \nCleartext pattern evaluation of: " << inputStr2 << " is " << result2 << ".");
		PROFILELOG( "Evaluation 2 execution time: " << "\t" << timeEval2 << " ms" );

		if (result2 != out2) {
			std::cout << "ERROR EVALUATING 2"<< std::endl;
			errorflag |= true;
		}
	}

	if (n_evals > 2)  {
		PROFILELOG("Evaluation 3 started");
		TIC(t1);
		result3 = algorithm.Evaluate(obfuscatedPattern,inputStr3);
		timeEval3 = TOC(t1);
		DEBUG( "\nCleartext pattern evaluation of: " << inputStr3 << " is " << result3 << ".");
		PROFILELOG( "Evaluation 3 execution time: " << "\t" << timeEval3 << " ms");
		if (result3 != out3) {
			std::cout << "ERROR EVALUATING 3"<< std::endl;
			errorflag |= true;
		}
	}

	//get the total program run time.
	timeTotal = TOC(t_total);

	//print output timing results
	//note one could use PROFILELOG for these lines
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

	ILVector2n::DestroyPreComputedSamples();

	return (errorflag);
}


