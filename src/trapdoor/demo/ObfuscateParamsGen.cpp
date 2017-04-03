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
Description:
	Main simulation test script for conjunction obfuscator

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

#include "obfuscation/lweconjunctionobfuscatev3.h"
#include "obfuscation/lweconjunctionobfuscatev3.cpp"
#include "time.h"
#include <chrono>
#include "utils/debug.h"

//using namespace std;
using namespace lbcrypto;

void RunParamsGen();
void RunUniform();
//double currentDateTime();

int main(){

	RunParamsGen();

	RunUniform();

	std::cin.get();

	return 0;
}


void RunUniform() {

	usint m = 4096;
	BigBinaryInteger modulus(BigBinaryInteger("18014398509506561"));
	BigBinaryInteger rootOfUnity(BigBinaryInteger("5194839201355896"));

	ILParams ilParams(m, modulus, rootOfUnity);
	shared_ptr<ILParams> params = std::make_shared<ILParams>(ilParams);

	auto zero_alloc = ILVector2n::MakeAllocator(params, EVALUATION);
	auto gaussian_alloc = ILVector2n::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, SIGMA);
	auto uniform_alloc = ILVector2n::MakeDiscreteUniformAllocator(params, COEFFICIENT);

	size_t n = params->GetCyclotomicOrder() / 2;
	double val = params->GetModulus().ConvertToDouble();
	double logTwo = log(val - 1.0) / log(2) + 1.0;
	size_t k = (usint)floor(logTwo);

	double diff, start, finish;

	start = currentDateTime();

	RingMat u1(zero_alloc, 2, k, uniform_alloc);

	finish = currentDateTime();

	std::cout << "Uniform generation time: " << "\t" << (finish - start) << " ms" << std::endl;
}

//Main simulator
void RunParamsGen() {

	usint m = 2048;
	//54 bits
	//BigBinaryInteger modulus("9007199254741169");
	//BigBinaryInteger rootOfUnity("7629104920968175");

	usint chunkSize = 1;
	std::string inputPattern = "1?101";
	ClearLWEConjunctionPattern<ILVector2n> clearPattern(inputPattern);

	ObfuscatedLWEConjunctionPattern<ILVector2n> obfuscatedPattern;
	obfuscatedPattern.SetChunkSize(chunkSize);
	obfuscatedPattern.SetLength(clearPattern.GetLength());
	obfuscatedPattern.SetRootHermiteFactor(1.006);

	LWEConjunctionObfuscationAlgorithm<ILVector2n> algorithm;

	double stdDev = SIGMA;

	double diff, start, finish;


	//DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(modulus, stdDev);			// Create the noise generator
	DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(stdDev); // Create the noise generator

	start = currentDateTime();

	//Finds q using the correctness constraint for the given value of n
	algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);

	finish = currentDateTime();

	std::cout << "Parameter generation: " << "\t" << (finish - start) << " ms" << std::endl;

	//this code finds the values of q and n corresponding to the root Hermite factor in obfuscatedPattern
	//algorithm.ParamsGen(dgg, &obfuscatedPattern);

	const shared_ptr<ILParams> ilParams = std::dynamic_pointer_cast<ILParams>(obfuscatedPattern.GetParameters());

	const BigBinaryInteger &modulus = ilParams->GetModulus();
	const BigBinaryInteger &rootOfUnity = ilParams->GetRootOfUnity();
	m = ilParams->GetCyclotomicOrder();

	std::cout << "q = " << modulus<< std::endl;
	std::cout << "log2q = " << modulus.GetMSB() << std::endl;
	std::cout << "rootOfUnity = " << rootOfUnity << std::endl;
	std::cout << "n = " << m/2 << std::endl;
	std::cout << printf("delta=%lf", obfuscatedPattern.GetRootHermiteFactor()) << std::endl;

}


