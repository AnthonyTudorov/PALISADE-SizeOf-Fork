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

#include "../../lib/obfuscate/lweconjunctionobfuscatev2.h"
#include "../../lib/obfuscate/lweconjunctionobfuscatev2.cpp"
//#include "../../lib/obfuscate/obfuscatelp.h"
#include "time.h"
#include <chrono>
#include "../../lib/utils/debug.h"

//using namespace std;
using namespace lbcrypto;

void NTRUPRE(int input);
//double currentDateTime();

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

	NTRUPRE(input);

	std::cin.get();

	return 0;
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
	//47 bits
	BigBinaryInteger modulus("35184372088961");
	BigBinaryInteger rootOfUnity("21593505674172");

	float stdDev = 4;

	double diff, start, finish;

	//Prepare for parameters.
	shared_ptr<ILParams> ilParams( new ILParams(m,modulus,rootOfUnity) );

	//DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(modulus, stdDev);			// Create the noise generator
	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(stdDev); // Create the noise generator
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);
	TernaryUniformGenerator tug = TernaryUniformGenerator();			// Create the noise generator

	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	start = currentDateTime();

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Precomputation time: " << "\t" << diff << " ms" << std::endl;

	//start = currentDateTime();

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	usint chunkSize = 2;
	std::string inputPattern = "1?10?1";
	//	std::string inputPattern = "1?1";
	//std::string inputPattern = "1";
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);

	LWEConjunctionObfuscationAlgorithmV2<ILVector2n> algorithm;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	std::cout << " \nCleartext pattern length: " << std::endl;
	std::cout << clearPattern.GetLength() << std::endl;

	//std::string inputStr1 = "1";
	std::string inputStr1 = "111001";
	//std::string inputStr1 = "101";
	bool out1 = algorithm.Evaluate(clearPattern,inputStr1);
	std::cout << " \nCleartext pattern evaluation of: " << inputStr1 << std::endl;
	std::cout << out1 << std::endl;

	//std::string inputStr2 = "1";
	std::string inputStr2 = "110011";
	//std::string inputStr2 = "100";
	bool out2 = algorithm.Evaluate(clearPattern,inputStr2);
	std::cout << " \nCleartext pattern evaluation of: " << inputStr2 << std::endl;
	std::cout << out2 << std::endl;

	//std::string inputStr3 = "101100";
	std::string inputStr3 = "101011";
	//std::string inputStr3 = "0";
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

	ObfuscatedLWEConjunctionPatternV2<ILVector2n> obfuscatedPattern(ilParams,chunkSize);
	obfuscatedPattern.SetLength(clearPattern.GetLength());

	std::cout << "Key generation started" << std::endl;

	start = currentDateTime();

	algorithm.KeyGen(dgg,&obfuscatedPattern);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Key generation ended" << std::endl;

	std::cout << "Key generation time: " << "\t" << diff << " ms" << std::endl;	

	algorithm.Obfuscate(clearPattern,dgg,tug,&obfuscatedPattern);
	std::cout << "Obfuscation Execution completed." << std::endl;

//	obfuscatedPattern.GetSl();

	result = algorithm.Evaluate(obfuscatedPattern,inputStr1);
	std::cout << " \nObfuscated pattern evaluation of: " << inputStr1 << " is " << result << "." <<std::endl;

	result = algorithm.Evaluate(obfuscatedPattern,inputStr2);
	std::cout << " \nObfuscated pattern evaluation of: " << inputStr2 << " is " << result << "." <<std::endl;

	result = algorithm.Evaluate(obfuscatedPattern,inputStr3);
	std::cout << " \nObfuscated pattern evaluation of: " << inputStr3 << " is " << result << "." <<std::endl;

	//system("pause");

}


