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

using namespace std;
using namespace lbcrypto;

void NTRUPRE(int input, bool dbg_flag);
double currentDateTime();

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

int main(int argc, char* argv[]){

	int input = 0;
	if (argc < 2) { // called with no arguments
	  cout << "arg 1 = Relinearization window : " << endl;
	  cout << "0 (n = 8), 1 (n = 16), 2 (n = 32), 3 (n = 64), 4 (n = 128), 5 (n = 256), 6 (n = 512), 7 (n = 1024): [0] ";
	  cout << "arg 2 = debugflag 0:1 [0] " << endl;
	  cin >> input;
	  //cleans up the buffer
	  cin.ignore();
	  
	} else {
	  input = atoi(argv[1]);
	}

	if ((input<0) || (input>7)) {
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
	
	NTRUPRE(input, dbg_flag);

	//std::cin.get();

	return 0;
}


double currentDateTime()
{

	std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

    time_t tnow = std::chrono::system_clock::to_time_t(now);
    tm *date = localtime(&tnow);
    date->tm_hour = 0;
    date->tm_min = 0;
    date->tm_sec = 0;

    auto midnight = std::chrono::system_clock::from_time_t(mktime(date));

	return std::chrono::duration <double, std::milli>(now - midnight).count();
}

typedef std::chrono::high_resolution_clock::time_point TimeVar;

#define duration(a) std::chrono::duration_cast<std::chrono::milliseconds>(a).count()
#define timeNow() std::chrono::high_resolution_clock::now()

template<typename F, typename... Args>
double funcTime(F func, Args&&... args){
    TimeVar t1=timeNow();
    func(std::forward<Args>(args)...);
    return duration(timeNow()-t1);
}

#define TIC t1=timeNow() 
#define TOC duration(timeNow()-t1)

#define TOTAL_TIC t2=timeNow() 
#define TOTAL_TOC duration(timeNow()-t2)


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
  
	TimeVar t1,t2; //for TIC TOC and TOTAL_TIC TOTAL_TOC
	TOTAL_TIC;

	//Set element params

	// Remove the comments on the following to use a low-security, highly efficient parameterization for integration and debugging purposes.

	//usint m = 16;
	//BigBinaryInteger modulus("67108913");
	//BigBinaryInteger rootOfUnity("61564");

	SecureParams const SECURE_PARAMS[] = {
		{ 16,	BigBinaryInteger("67108913"),	BigBinaryInteger("61564"),	0},
		{ 32,	BigBinaryInteger("67108961"),	BigBinaryInteger("21324232"), 	0},
		{ 64,	BigBinaryInteger("67109633"),	BigBinaryInteger("44127055"),	0},
		{ 128,	BigBinaryInteger("67109633"),	BigBinaryInteger("14106214"),	0},
		{ 256,	BigBinaryInteger("67109633"),	BigBinaryInteger("44083227"),	0},
		{ 512,	BigBinaryInteger("67118593"),	BigBinaryInteger("15034782"),	0},
		{ 1024,	BigBinaryInteger("67126273"),	BigBinaryInteger("43023954"),	0},
		{ 2048,	BigBinaryInteger("67127297"),	BigBinaryInteger("19715182"),	0}
	};

	usint m = SECURE_PARAMS[input].m;
	BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);

	float stdDev = 4;

	//Variables for timing
	double timeFFTSetup, timeDGGSetup, timeKeyGen, 
	  timeObf, timeEval1, timeEval, timeTotal; 


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
	TIC;
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);
	timeFFTSetup = TOC;
	DEBUG("FFT Precomputation time: " << "\t" << timeFFTSetup << " ms");

	//Precomputations for DGG
	TIC;
	ILVector2n::PreComputeDggSamples(dgg, ilParams);
	timeDGGSetup = TOC;
	DEBUG("DGG Precomputation time: " << "\t" << timeDGGSetup << " ms");

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	//	std::string inputPattern = "10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?1";  //DBC: pick a much shorter string for debugging
	std::string inputPattern = "10?10?";
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);

	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	DEBUG(" \nCleartext pattern: ");
	DEBUG(clearPattern.GetPatternString());

	DEBUG(" \nCleartext pattern length: ");
	DEBUG(clearPattern.GetLength());

	//std::string inputStr1 = "1001001001001001001001001001001001001001001001001001001001001001";
	std::string inputStr1 = "100100";
	bool out1 = algorithm.Evaluate(clearPattern,inputStr1);
	DEBUG(" \nCleartext pattern evaluation of: " << inputStr1);
	DEBUG(out1);

	//std::string inputStr2 = "101";
	//bool out2 = algorithm.Evaluate(clearPattern,inputStr2);
	//DEBUG(" \nCleartext pattern evaluation of: " << inputStr2);
	//DEBUG(out2);

	//std::string inputStr3 = "001";
	//bool out3 = algorithm.Evaluate(clearPattern,inputStr3);
	//DEBUG(" \nCleartext pattern evaluation of: " << inputStr3);
	//DEBUG(out3);

	////////////////////////////////////////////////////////////
	//Generate and test the obfuscated pattern
	////////////////////////////////////////////////////////////
	bool result;

	cout << " \nCleartext pattern: " << endl;
	cout << clearPattern.GetPatternString() << endl;

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(ilParams);
	obfuscatedPattern.SetLength(clearPattern.GetLength());

	DEBUG( "Key generation started"); 
	TIC;
	algorithm.KeyGen(dgg,&obfuscatedPattern);
	timeKeyGen = TOC;
	DEBUG( "Key generation time: " << "\t" << timeKeyGen << " ms");
	

	DEBUG( "Obfuscation Execution started");
	TIC;
	algorithm.Obfuscate(clearPattern,dgg,dug,&obfuscatedPattern);
	timeObf = TOC;
	DEBUG("Obfuscation execution time: " << "\t" << timeObf << " ms");

//	obfuscatedPattern.GetSl();

	DEBUG("Evaluation started");
	TIC;
	result = algorithm.Evaluate(obfuscatedPattern,inputStr1);
	timeEval = TOC;
	cout << "Evaluation execution time: " << "\t" << timeEval << " ms" << endl;

	//get the total program run time.
	timeTotal = TOTAL_TOC;

	//print output timing results

	cout << "Timing Summary" << endl;
	cout << "FFT Precomputation time: " << "\t" << timeFFTSetup << " ms" << endl;
	cout << "DGG Precomputation time: " << "\t" << timeDGGSetup << " ms" << endl;
	cout << "Key generation time:        " << "\t" << timeKeyGen << " ms" << endl;
	cout << "Obfuscation execution time: " << "\t" << timeObf << " ms" << endl;
	cout << "Evaluation execution time:  " << "\t" << timeEval << " ms" << endl;
	cout << "Total execution time:       " << "\t" << timeTotal << " ms" << endl;

	cout << "\% Key generation time:        " << "\t" << timeKeyGen/timeTotal*100.0 << "\%" << endl;
	cout << "\% Obfuscation execution time: " << "\t" << timeObf/timeTotal*100.0 << "\%" << endl;
	cout << "\% Evaluation execution time:  " << "\t" << timeEval/timeTotal*100.0 << "\%" << endl;

	cout << "total measured time  is : "<< (timeFFTSetup + timeDGGSetup + timeKeyGen + timeObf + timeEval)/timeTotal *100.00<< "\%" << endl;
	
}

