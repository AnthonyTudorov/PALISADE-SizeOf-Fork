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
#include <math.h> 
#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

void NTRUPRE(int input);

void NextQ(BigBinaryInteger &q, const BigBinaryInteger &plainTextModulus, const usint &ringDimension);

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint n;			///< The ring parameter.
//	BigBinaryInteger modulus;	///< The modulus
//	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint length;		///< The relinearization window parameter.
};

int main(){
/*
	int input = 0;
	
	std::cout << "Relinearization window : " << std::endl;
	std::cout << "0 (n = 8), 1 (n = 16), 2 (n = 32), 3 (n = 64), 4 (n = 128), 5 (n = 256), 6 (n = 512), 7 (n = 1024): [0] ";

	std::cin >> input;
	//cleans up the buffer
	cin.ignore();

	if ((input<0) || (input>7))
		input = 0;
*/
	for (int input=0; input<32; input++) {
		NTRUPRE(input);
	}

	std::cin.get();

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

	//usint m = 16;
	//BigBinaryInteger modulus("67108913");
	//BigBinaryInteger rootOfUnity("61564");

	SecureParams const SECURE_PARAMS[] = {
		{ 8,	8},
		{ 8,	16},
		{ 8,	32},
		{ 8,	64},

		{ 16,	8},
		{ 16,	16},
		{ 16,	32},
		{ 16,	64},

		{ 32,	8},
		{ 32,	16},
		{ 32,	32},
		{ 32,	64},

		{ 64,	8},
		{ 64,	16},
		{ 64,	32},
		{ 64,	64},

		{ 128,	8}, 
		{ 128,	16},
		{ 128,	32},
		{ 128,	64},

		{ 256,	8},
		{ 256,	16},
		{ 256,	32},
		{ 256,	64},

		{ 512,	8},
		{ 512,	16},
		{ 512,	32},
		{ 512,	64},

		{ 1024,	8},
		{ 1024,	16},
		{ 1024,	32},
		{ 1024,	64},
	};

	//input = 0;

	usint n = SECURE_PARAMS[input].n;
	usint len = SECURE_PARAMS[input].length;

	float stdDev = 4.0;
	usint m=2*n;

	BigBinaryInteger modulus("64");
	usint logModulus = 6;
	usint logModulusPlus2 = 8;//15*len+2;
	usint logModulusPlus2Old = 8;

	bool logModulusUnchanged = false;

	while (!logModulusUnchanged) {


		float alpha = 3.0;
		float B1 = alpha*stdDev;

		float beta = 4.0;
		float sqrtnm = sqrt((float)(n*logModulusPlus2));

		float B2 = beta*40.0*sqrtnm;

		float front = 16.0*len*B1;
		float base = B2*sqrtnm;

		usint frontInt = ceil(front);
		usint baseInt = ceil(base);
	
		std::cout << "B1     : " << B1 << std::endl;
		std::cout << "B2     : " << B2 << std::endl;
		std::cout << "front  : " << front << std::endl;
		std::cout << "base   : " << base << std::endl;

		BigBinaryInteger frontBBI(frontInt);
		BigBinaryInteger baseBBI(baseInt);

		std::cout << "front  : " << frontBBI << std::endl;
		std::cout << "base   : " << baseBBI << std::endl;
	
		BigBinaryInteger baseBBIExp = baseBBI.Exp(len);
		std::cout << "base^L : " << baseBBIExp << std::endl;

		modulus = frontBBI * baseBBIExp;

		std::cout << "modulus estimate : " << modulus << std::endl;

		double val = modulus.ConvertToDouble();
		//std::cout << "val : " << val << std::endl;
		double logTwo = log(val-1.0)/log(2)+1.0;
		//std::cout << "logTwo : " << logTwo << std::endl;
		logModulus = (usint) floor(logTwo);// = this->m_cryptoParameters.GetModulus();
		logModulusPlus2 = logModulus+2;// = this->m_cryptoParameters.GetModulus();
		if (logModulusPlus2Old < logModulusPlus2) {
			logModulusPlus2Old = logModulusPlus2;
		} else {
			logModulusUnchanged = true;
		}
	}

	BigBinaryInteger rootOfUnity("1");

	
	std::cout << "modulus bits: " << logModulus << std::endl;
	std::cout << "modulus: " << modulus << std::endl;
	NextQ(modulus, BigBinaryInteger::TWO,n);
	std::cout << "modulus: " << modulus << std::endl;

	rootOfUnity = RootOfUnity(m,modulus);

	double diff, diffKeyGen, diffObf, diffEval, start, finish;

	//Prepare for parameters.
	ILParams ilParams(m,modulus,rootOfUnity);

	//Set crypto parametes
	//LPCryptoParametersLWE<ILVector2n> cryptoParams;
	//cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	//cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	//DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(modulus, stdDev);			// Create the noise generator
	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(stdDev);			// Create the noise generator
	DiscreteUniformGenerator dug = DiscreteUniformGenerator(modulus);
	BinaryUniformGenerator bug = BinaryUniformGenerator();			// Create the noise generator

	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	start = currentDateTime();

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Precomputation time: " << "\t" << diff << " ms" << endl;

	//start = currentDateTime();

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	std::string inputPattern = "10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?10?1";
	inputPattern.resize(len);
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);

	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	std::cout << " \nCleartext pattern length: " << std::endl;
	std::cout << clearPattern.GetLength() << std::endl;

	std::string inputStr1 = "1001001001001001001001001001001001001001001001001001001001001001";
	inputStr1.resize(len);
	bool out1 = algorithm.Evaluate(clearPattern,inputStr1);
	std::cout << " \nCleartext pattern evaluation of: " << inputStr1 << std::endl;
	std::cout << out1 << std::endl;

	//std::string inputStr2 = "101";
	//bool out2 = algorithm.Evaluate(clearPattern,inputStr2);
	//std::cout << " \nCleartext pattern evaluation of: " << inputStr2 << std::endl;
	//std::cout << out2 << std::endl;

	//std::string inputStr3 = "001";
	//bool out3 = algorithm.Evaluate(clearPattern,inputStr3);
	//std::cout << " \nCleartext pattern evaluation of: " << inputStr3 << std::endl;
	//std::cout << out3 << std::endl;

	////////////////////////////////////////////////////////////
	//Generate and test the obfuscated pattern
	////////////////////////////////////////////////////////////


//	Ciphertext<ILVector2n> ciphertext;
//	algorithm.Encrypt(pk,dgg,ptxt,&ciphertext);	// This is the core encryption operation.

	bool result;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern(ilParams);
	obfuscatedPattern.SetLength(clearPattern.GetLength());

	std::cout << "Key generation started" << std::endl;
	std::cout << "+START KeyGeneration " << m/2 << " " << logModulus << " " << len << std::endl;

	start = currentDateTime();

	algorithm.KeyGen(dgg,&obfuscatedPattern);

	finish = currentDateTime();
	diffKeyGen = finish - start;

	std::cout << "+END" << std::endl;
	std::cout << "Key generation ended" << std::endl;

	std::cout << "Key generation time: " << "\t" << diffKeyGen << " ms" << std::endl;

	std::cout << "Obfuscation Execution started" << std::endl;
	std::cout << "+START Obfuscation " << m/2 << " " << logModulus << " " << len << std::endl;

	start = currentDateTime();

	algorithm.Obfuscate(clearPattern,dgg,bug,&obfuscatedPattern);

	finish = currentDateTime();
	diffObf = finish - start;

	std::cout << "+END" << std::endl;
	std::cout << "Obfuscation Execution completed." << std::endl;

	std::cout << "Obfuscation execution time: " << "\t" << diffObf << " ms" << std::endl;

//	obfuscatedPattern.GetSl();


	std::cout << "Evaluation started" << std::endl;
	std::cout << "+START Evaluation " << m/2 << " " << logModulus << " " << len << std::endl;

	start = currentDateTime();

	result = algorithm.Evaluate(obfuscatedPattern,inputStr1);

	finish = currentDateTime();
	diffEval = finish - start;

	std::cout << "+END" << std::endl;
	std::cout << "Evaluation completed." << std::endl;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

	std::cout << " \nCleartext pattern evaluation of: " << inputStr1 << " is " << result << "." <<std::endl;

	std::cout << "Key generation time: " << "\t" << diffKeyGen << " ms" << std::endl;
	std::cout << "Obfuscation execution time: " << "\t" << diffObf << " ms" << std::endl;
	std::cout << "Evaluation execution time: " << "\t" << diffEval << " ms" << std::endl;


	//system("pause");

}


void NextQ(BigBinaryInteger &q, 
		const BigBinaryInteger &plainTextModulus, 
		const usint &ringDimension) {
	BigBinaryInteger bigOne("1");
	BigBinaryInteger bigTwo("2");
	BigBinaryInteger ringDimensions(ringDimension);

	q = q + bigOne;

	while (q.Mod(plainTextModulus) != bigOne) {
		q = q + bigOne;
	}

	BigBinaryInteger cyclotomicOrder = ringDimensions * bigTwo;

	while (q.Mod(cyclotomicOrder) != bigOne) {
		q = q + plainTextModulus;
	}

	BigBinaryInteger productValue = cyclotomicOrder * plainTextModulus;

	while (!MillerRabinPrimalityTest(q)) {
		q = q + productValue;
	}

/*
	BigBinaryInteger gcd;
	gcd = GreatestCommonDivisor(q - BigBinaryInteger::ONE, ringDimensions);

	if(!(ringDimensions == gcd)){
		q = q + BigBinaryInteger::ONE;
	  	NextQ(q, plainTextModulus, ringDimension);
	}
*/

}
