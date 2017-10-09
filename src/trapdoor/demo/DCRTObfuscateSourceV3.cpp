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

#include <iostream>
#include <fstream>

#include "obfuscation/lweconjunctionobfuscate.h"
#include "obfuscation/lweconjunctionobfuscate.cpp"
#include "time.h"
#include <chrono>
#include "utils/debug.h"

//using namespace std;
using namespace lbcrypto;

void Run();
//double currentDateTime();

int main(){

	Run();

	std::cin.get();

	return 0;
}


//Main simulator
void Run() {

	usint m = 16;
	//54 bits
	//BigInteger modulus("9007199254741169");
	//BigInteger rootOfUnity("7629104920968175");

	usint chunkSize = 2;
	usint base = 1<<6;
	std::string inputPattern = "1?10?1";
	ClearLWEConjunctionPattern<DCRTPoly> clearPattern(inputPattern);

	ObfuscatedLWEConjunctionPattern<DCRTPoly> obfuscatedPattern;
	obfuscatedPattern.SetChunkSize(chunkSize);
	obfuscatedPattern.SetBase(base);
	obfuscatedPattern.SetLength(clearPattern.GetLength());
	obfuscatedPattern.SetRootHermiteFactor(1.006);

	LWEConjunctionObfuscationAlgorithm<DCRTPoly> algorithm;

	double stdDev = SIGMA;

	double diff, start, finish;

	DCRTPoly::DggType dgg(stdDev);			// Create the noise generator

	//Finds q using the correctness constraint for the given value of n
	algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);

	//this code finds the values of q and n corresponding to the root Hermite factor in obfuscatedPattern
	//algorithm.ParamsGen(dgg, &obfuscatedPattern);

	const shared_ptr<typename DCRTPoly::Params> ilParams = obfuscatedPattern.GetParameters();

	const BigInteger &modulus = ilParams->GetModulus();
	const BigInteger &rootOfUnity = ilParams->GetRootOfUnity();
	m = ilParams->GetCyclotomicOrder();

	std::cout << "q = " << modulus<< std::endl;
	std::cout << "rootOfUnity = " << rootOfUnity << std::endl;
	std::cout << "n = " << m/2 << std::endl;
	std::cout << printf("delta=%lf", obfuscatedPattern.GetRootHermiteFactor()) << std::endl;

	typename DCRTPoly::TugType tug;

	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	start = currentDateTime();

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	//ChineseRemainderTransformFTT<BigInteger,BigVector>::GetInstance().PreCompute(rootOfUnity, m, modulus);
	DiscreteFourierTransform::GetInstance().PreComputeTable(m);

	//Precomputations for DGG
	//DCRTPoly::PreComputeDggSamples(dgg, ilParams);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Precomputation time: " << "\t" << diff << " ms" << std::endl;

	//start = currentDateTime();

	////////////////////////////////////////////////////////////
	//Generate and test the cleartext pattern
	////////////////////////////////////////////////////////////

	//	std::string inputPattern = "1?1";
	//std::string inputPattern = "1";

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

	bool result;

	std::cout << " \nCleartext pattern: " << std::endl;
	std::cout << clearPattern.GetPatternString() << std::endl;

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
	std::cout << " \nObfuscated pattern evaluation (Original) of: " << inputStr1 << " is " << result << "." <<std::endl;
	result = algorithm.Evaluate(obfuscatedPattern,inputStr1);
	std::cout << " \nObfuscated pattern evaluation of : " << inputStr1 << " is " << result << "." <<std::endl;


	result = algorithm.Evaluate(obfuscatedPattern,inputStr2);
	std::cout << " \nObfuscated pattern evaluation (Original) of: " << inputStr2 << " is " << result << "." <<std::endl;
	result = algorithm.Evaluate(obfuscatedPattern,inputStr2);
	std::cout << " \nObfuscated pattern evaluation : " << inputStr2 << " is " << result << "." <<std::endl;


	result = algorithm.Evaluate(obfuscatedPattern,inputStr3);
	std::cout << " \nObfuscated pattern evaluation (Original) of: " << inputStr3 << " is " << result << "." <<std::endl;
	result = algorithm.Evaluate(obfuscatedPattern,inputStr3);
	std::cout << " \nObfuscated pattern evaluation of : " << inputStr3 << " is " << result << "." <<std::endl;
	//system("pause");

	DiscreteFourierTransform::GetInstance().Destroy();
}


