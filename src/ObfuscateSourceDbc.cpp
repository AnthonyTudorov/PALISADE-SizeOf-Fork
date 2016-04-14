﻿//Hi Level Execution/Demonstration
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
//#include "utils/inttypes.h"
//#include "math/backend.h"
//#include "math/nbtheory.h"
//#include "math/distrgen.h"
//#include "lattice/elemparams.h"
//#include "lattice/ilparams.h"
//#include "lattice/ildcrtparams.h"
//#include "lattice/ilelement.h"
//#include "crypto/lwecrypt.h"
#include "obfuscate/lweconjunctionobfuscate.h"
#include "obfuscate/lweconjunctionobfuscate.cpp"
//#include "obfuscate/obfuscatelp.h"
#include "time.h"
#include <chrono>
#include "utils/debug.h"
//todo (dcousins): migrate this to utils/debug.cpp

#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;

void NTRUPRE(int input, bool dbg_flag);
// double currentDateTime();

// /**
//  * @brief Input parameters for PRE example.
//  */
// struct SecureParams {
// 	usint m;			///< The ring parameter.
// 	BigBinaryInteger modulus;	///< The modulus
// 	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
// 	usint relinWindow;		///< The relinearization window parameter.
// };

//main()   need this for Kurts makefile to ignore this.
int main(int argc, char* argv[]){

	int input = 0;

 	if (argc < 2) { // called with no arguments

	  cout << "arg 1 = Relinearization window : " << endl;
	  cout << "0 (r = 1), 1 (r = 2), 2 (r = 4), 3 (r = 8), 4 (r = 16): [0] ";
	  cout << "arg 2 = debugflag 0:1 [0] " << endl;
	  cin >> input;
	  //cleans up the buffer
	  cin.ignore();
	  
	} else {
	  input = atoi(argv[1]);
	}

	if ((input<0) || (input>4)) {
	  cerr << "input " << input << "outside of allowed range [0..7], set to 0" << endl;
	  input = 0;
	}
	bool dbg_flag = false; 

	if (argc > 2 ) {
	  if (atoi(argv[2]) != 0) {
#ifndef NDEBUG
	    dbg_flag = true;
	    cout << "setting dbg_flag true" << endl;
#endif
	  }
	}

	cerr  <<"Running " << argv[0] <<" with "<< omp_get_num_procs() << " processors." << endl;

	NTRUPRE(input, dbg_flag);

	//std::cin.get();

	return 0;
}


// double currentDateTime()
// {

// 	std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

//     time_t tnow = std::chrono::system_clock::to_time_t(now);
//     tm *date = localtime(&tnow);
//     date->tm_hour = 0;
//     date->tm_min = 0;
//     date->tm_sec = 0;

//     auto midnight = std::chrono::system_clock::from_time_t(mktime(date));

// 	return std::chrono::duration <double, std::milli>(now - midnight).count();
// }

// typedef std::chrono::high_resolution_clock::time_point TimeVar;

// #define duration(a) std::chrono::duration_cast<std::chrono::milliseconds>(a).count()
// #define timeNow() std::chrono::high_resolution_clock::now()

// template<typename F, typename... Args>
// double funcTime(F func, Args&&... args){
//     TimeVar t1=timeNow();
//     func(std::forward<Args>(args)...);
//     return duration(timeNow()-t1);
// }

// #define TIC t1=timeNow() 
// #define TOC duration(timeNow()-t1)

// #define TOTAL_TIC t2=timeNow() 
// #define TOTAL_TOC duration(timeNow()-t2)


typedef std::string String;  //dbc shortcut

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
void NTRUPRE(int input, bool dbg_flag) {
  
	TimeVar t1,t_total; //for TIC TOC and TOTAL_TIC TOTAL_TOC
	TIC(t_total);

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
	double timeFFTSetup, timeDGGSetup, timeKeyGen, 
	  timeObf, timeBUGGen, timeEval1, timeEval2, timeEval3, timeTotal; 


	//Prepare for parameters.
	ILParams ilParams(m,modulus,rootOfUnity);

	//Set crypto parametes
	//LPCryptoParametersLWE<ILVector2n> cryptoParams;
	//cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	//cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(modulus, stdDev);			// Create the noise generator
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);
	BinaryUniformGenerator bug = BinaryUniformGenerator();			// Create the noise generator

	DEBUG("Cryptosystem initialization: Performing precomputations...");

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	TIC(t1);
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);
	timeFFTSetup = TOC(t1);
	DEBUG("FFT Precomputation time: " << "\t" << timeFFTSetup << " ms");

	//Precomputations for DGG
	TIC(t1);
	ILVector2n::PreComputeDggSamples(dgg, ilParams);
	timeDGGSetup = TOC(t1);
	DEBUG("DGG Precomputation time: " << "\t" << timeDGGSetup << " ms");

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	std::string inputPattern = "10?";
	//std::string inputPattern = "1";
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);

	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	DEBUG(" \nCleartext pattern: ");
	DEBUG(clearPattern.GetPatternString());

	DEBUG(" \nCleartext pattern length: ");
	DEBUG(clearPattern.GetLength());

	//std::string inputStr1 = "1";
	std::string inputStr1 = "100";
	bool out1 = algorithm.Evaluate(clearPattern,inputStr1);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr1);
	DEBUG(out1);

	//std::string inputStr2 = "1";
	std::string inputStr2 = "101";

	bool out2 = algorithm.Evaluate(clearPattern,inputStr2);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr2);
	DEBUG(out2);
	
	std::string inputStr3 = "010";
	//std::string inputStr3 = "0";
	bool out3 = algorithm.Evaluate(clearPattern,inputStr3);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr3);
	DEBUG(out3);

	////////////////////////////////////////////////////////////
	//Generate and test the obfuscated pattern
	////////////////////////////////////////////////////////////


//	Ciphertext<ILVector2n> ciphertext;
//	algorithm.Encrypt(pk,dgg,ptxt,&ciphertext);	// This is the core encryption operation.

	bool result;

	cout << " \nCleartext pattern: " << endl;
	cout << clearPattern.GetPatternString() << endl;

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(ilParams);
	obfuscatedPattern.SetLength(clearPattern.GetLength());

	DEBUG( "Key generation started"); 
	TIC(t1);
	algorithm.KeyGen(dgg,&obfuscatedPattern);
	timeKeyGen = TOC(t1);
	DEBUG( "Key generation time: " << "\t" << timeKeyGen << " ms");

	
	DEBUG( "Binary Uniform Generator started"); 
	TIC(t1);
	BinaryUniformGenerator dbg = BinaryUniformGenerator();	
	timeBUGGen = TOC(t1);
	DEBUG( "Key generation time: " << "\t" << timeBUGGen << " ms");


	DEBUG( "Obfuscation Execution started");
	TIC(t1);
	algorithm.Obfuscate(clearPattern,dgg,dbg,&obfuscatedPattern);
	timeObf = TOC(t1);
	DEBUG("Obfuscation execution time: " << "\t" << timeObf << " ms");

//	obfuscatedPattern.GetSl();

	DEBUG("Evaluation 1 started");
	TIC(t1);
	result = algorithm.Evaluate(obfuscatedPattern,inputStr1);
	timeEval1 = TOC(t1);
	DEBUG( " \nCleartext pattern evaluation of: " << inputStr1 << " is " << result << ".");
	DEBUG( "Evaluation 1 execution time: " << "\t" << timeEval1 << " ms" );

	DEBUG("Evaluation 2 started");
	TIC(t1);
	//result = algorithm.Evaluate(obfuscatedPattern,inputStr2);
	//DEBUG( " \nCleartext pattern evaluation of: " << inputStr2 << " is " << result << ".");
	timeEval2 = TOC(t1);
	DEBUG( "Evaluation 2 execution time: " << "\t" << timeEval2 << " ms" );

	DEBUG("Evaluation 3 started");
	TIC(t1);
	//result = algorithm.Evaluate(obfuscatedPattern,inputStr3);
	//DEBUG( " \nCleartext pattern evaluation of: " << inputStr3 << " is " << result << ".");
	timeEval3 = TOC(t1);
	DEBUG( "Evaluation 3 execution time: " << "\t" << timeEval3 << " ms");

	//get the total program run time.
	timeTotal = TOC(t_total);

	//print output timing results

	cout << "Timing Summary" << endl;
	cout << "FFT Precomputation time: " << "\t" << timeFFTSetup << " ms" << endl;
	cout << "DGG Precomputation time: " << "\t" << timeDGGSetup << " ms" << endl;
	cout << "T: Key generation time:        " << "\t" << timeKeyGen << " ms" << endl;
	cout << "Binary Uniform generation time:        " << "\t" << timeBUGGen << " ms" << endl;
	cout << "T: Obfuscation execution time: " << "\t" << timeObf << " ms" << endl;
	cout << "T: Evaluation 1 execution time:  " << "\t" << timeEval1 << " ms" << endl;
	cout << "Evaluation 2 execution time:  " << "\t" << timeEval2 << " ms" << endl;
	cout << "Evaluation 3 execution time:  " << "\t" << timeEval3 << " ms" << endl;

	cout << "Total execution time:       " << "\t" << timeTotal << " ms" << endl;

	
}


