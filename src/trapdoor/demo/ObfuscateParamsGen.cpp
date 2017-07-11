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
	BigInteger modulus(BigInteger("18014398509506561"));
	BigInteger rootOfUnity(BigInteger("5194839201355896"));

	ILParams ilParams(m, modulus, rootOfUnity);
	shared_ptr<ILParams> params = std::make_shared<ILParams>(ilParams);

	auto zero_alloc = Poly::MakeAllocator(params, EVALUATION);
	auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(params, COEFFICIENT, SIGMA);
	auto uniform_alloc = Poly::MakeDiscreteUniformAllocator(params, COEFFICIENT);

	double val = params->GetModulus().ConvertToDouble();
	double logTwo = log(val - 1.0) / log(2) + 1.0;
	size_t k = (usint)floor(logTwo);

	double start, finish;

	start = currentDateTime();

	RingMat u1(zero_alloc, 2, k, uniform_alloc);

	finish = currentDateTime();

	std::cout << "Uniform generation time: " << "\t" << (finish - start) << " ms" << std::endl;
}

//Main simulator
void RunParamsGen() {

	usint m = 4096;
	//54 bits
	//BigInteger modulus("9007199254741169");
	//BigInteger rootOfUnity("7629104920968175");

	usint chunkSize = 1;
	std::string inputPattern = "1?101";
	ClearLWEConjunctionPattern<Poly> clearPattern(inputPattern);

	ObfuscatedLWEConjunctionPattern<Poly> obfuscatedPattern;
	obfuscatedPattern.SetChunkSize(chunkSize);
	obfuscatedPattern.SetLength(clearPattern.GetLength());
	obfuscatedPattern.SetRootHermiteFactor(1.006);

	LWEConjunctionObfuscationAlgorithm<Poly> algorithm;

	double stdDev = SIGMA;

	double start, finish;


	Poly::DggType dgg(stdDev); // Create the noise generator

	start = currentDateTime();

	//Finds q using the correctness constraint for the given value of n
	algorithm.ParamsGen(dgg, &obfuscatedPattern, m / 2);

	finish = currentDateTime();

	std::cout << "Parameter generation: " << "\t" << (finish - start) << " ms" << std::endl;

	//this code finds the values of q and n corresponding to the root Hermite factor in obfuscatedPattern
	//algorithm.ParamsGen(dgg, &obfuscatedPattern);

	const shared_ptr<ILParams> ilParams = std::dynamic_pointer_cast<ILParams>(obfuscatedPattern.GetParameters());

	const BigInteger &modulus = ilParams->GetModulus();
	const BigInteger &rootOfUnity = ilParams->GetRootOfUnity();
	m = ilParams->GetCyclotomicOrder();

	std::cout << "q = " << modulus<< std::endl;
	std::cout << "log2q = " << modulus.GetMSB() << std::endl;
	std::cout << "rootOfUnity = " << rootOfUnity << std::endl;
	std::cout << "n = " << m/2 << std::endl;
	std::cout << printf("delta=%lf", obfuscatedPattern.GetRootHermiteFactor()) << std::endl;

}


