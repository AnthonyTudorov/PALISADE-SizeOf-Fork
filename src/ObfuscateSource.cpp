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
#include "utils/inttypes.h"
#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "crypto/lwecrypt.h"
#include "obfuscate/lweconjunctionobfuscate.h"
//#include "obfuscate/lweconjunctionobfuscate.cpp"
#include "obfuscate/obfuscatelp.h"
#include "time.h"
#include <chrono>

using namespace std;
using namespace lbcrypto;

void NTRUPRE(int input);
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

int main(){

	int input = 0;
	/*
	std::cout << "Relinearization window : " << std::endl;
	std::cout << "0 (r = 1), 1 (r = 2), 2 (r = 4), 3 (r = 8), 4 (r = 16): [0] ";

	std::cin >> input;
	//cleans up the buffer
	cin.ignore();

	if ((input<0) || (input>4))
		input = 0;
	*/
	NTRUPRE(input);

	std::cin.get();

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
void NTRUPRE(int input) {

	//Set element params

	// Remove the comments on the following to use a low-security, highly efficient parameterization for integration and debugging purposes.

	usint m = 16;
	BigBinaryInteger modulus("67108913");
	//BigBinaryInteger modulus("61");
	BigBinaryInteger rootOfUnity("61564");
	//BigBinaryInteger rootOfUnity("6");
	float stdDev = 4;

	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	//Prepare for parameters.
	ILParams ilParams(m,modulus,rootOfUnity);

	//Set crypto parametes
	//LPCryptoParametersLWE<ILVector2n> cryptoParams;
	//cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	//cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(modulus, stdDev);			// Create the noise generator
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);
	BinaryUniformGenerator bug = BinaryUniformGenerator();			// Create the noise generator

	double diff, start, finish;
	//start = currentDateTime();

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	std::string inputPattern = "10?";
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);

	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	std::cout << " \nCleartext pattern length: " << std::endl;
	std::cout << clearPattern.GetLength() << std::endl;

	std::string inputStr1 = "100";
	bool out1 = algorithm.Evaluate(clearPattern,inputStr1);
	std::cout << " \nCleartext pattern evaluation of: " << inputStr1 << std::endl;
	std::cout << out1 << std::endl;

	std::string inputStr2 = "101";
	bool out2 = algorithm.Evaluate(clearPattern,inputStr2);
	std::cout << " \nCleartext pattern evaluation of: " << inputStr2 << std::endl;
	std::cout << out2 << std::endl;

	std::string inputStr3 = "001";
	bool out3 = algorithm.Evaluate(clearPattern,inputStr3);
	std::cout << " \nCleartext pattern evaluation of: " << inputStr3 << std::endl;
	std::cout << out3 << std::endl;

	////////////////////////////////////////////////////////////
	//Generate and test the obfuscated pattern
	////////////////////////////////////////////////////////////


//	Ciphertext<ILVector2n> ciphertext;
//	algorithm.Encrypt(pk,dgg,ptxt,&ciphertext);	// This is the core encryption operation.

	bool result;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(ilParams);
	algorithm.Obfuscate(clearPattern,dgg,dug,&obfuscatedPattern);
	std::cout << "Obfuscation Execution completed." << std::endl;

//	obfuscatedPattern.GetSl();

	result = algorithm.Evaluate(&obfuscatedPattern,inputStr1);
	std::cout << " \nCleartext pattern evaluation of: " << inputStr1 << " is " << result << "." <<std::endl;

	//system("pause");

}

