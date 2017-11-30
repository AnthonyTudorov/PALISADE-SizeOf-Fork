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

#define PROFILE  //define this to enable PROFILELOG and TIC/TOC
// Note must be before all headers

#include <iostream>
#include "obfuscation/lwetbolinearsecret.h"
#include "obfuscation/lwetbolinearsecret.cpp"

#include "utils/debug.h"

using namespace lbcrypto;

typedef typename LWETBOLinearSecret::NativeMatrixPtr NativeMatrixPtr;
typedef typename LWETBOLinearSecret::NativeMatrix NativeMatrix;

int main(int argc, char* argv[]) {
	TimeVar t;

	double processingTime(0.0);

	usint N = 1000;
	usint n = 2048;
	usint wmax = 4;
	usint pmax = 16;

	TIC(t);
	LWETBOLinearSecret algorithm(N, n, wmax, pmax);
	processingTime = TOC(t);
	std::cout << "Parameter Generation: " << processingTime << "ms" << std::endl;

	std::cout << "\nn = " << algorithm.GetSecurityParameter() << std::endl;
	std::cout << "log2 q = " << algorithm.GetLogModulus() << std::endl;
	std::cout << "weight norm = " << algorithm.GetWeightNorm() << std::endl;
	std::cout << "input data norm = " << pmax << std::endl;
	std::cout << "plaintext modulus = " << algorithm.GetPlaintextModulus() << std::endl;
	std::cout << "Dimension of weight/data vectors = " << algorithm.GetDimension() << std::endl;

	TIC(t);
	LWETBOKeys keys = algorithm.KeyGen();
	processingTime = TOC(t);
	std::cout << "\nKey generation time: " << processingTime << "ms" << std::endl;

	//std::cout << "secretkeys(0,0) = " << (*keys.m_secretKey)(0,0) << std::endl;
	//std::cout << "secretkeys(1,1) = " << (*keys.m_secretKey)(1,1) << std::endl;

	//std::cout << "Token row dimension = " << token->GetRows() << std::endl;
	//std::cout << "Token column dimension = " << token->GetCols() << std::endl;

	DiscreteUniformGeneratorImpl<NativeInteger,NativeVector> dugWeights;
	dugWeights.SetModulus(algorithm.GetWeightNorm());

	NativeMatrixPtr weights(new  NativeMatrix([&]() {
		return make_unique<NativeInteger>(dugWeights.GenerateInteger()); }, algorithm.GetDimension(),1));

	TIC(t);
	NativeMatrixPtr ciphertext = algorithm.Obfuscate(keys,weights);
	processingTime = TOC(t);
	std::cout << "\nObfuscation time: " << processingTime << "ms" << std::endl;\

	DiscreteUniformGeneratorImpl<NativeInteger,NativeVector> dug;
	dug.SetModulus(16);

	NativeMatrixPtr input(new  NativeMatrix([&]() {
		return make_unique<NativeInteger>(dug.GenerateInteger()); }, algorithm.GetDimension(),1));

	TIC(t);
	NativeMatrixPtr token = algorithm.TokenGen(keys.m_secretKey,input);
	processingTime = TOC(t);
	std::cout << "\nToken generation time: " << processingTime << "ms" << std::endl;

	//Generate parameters.
	double start, finish;

	start = currentDateTime();
	NativeInteger result = algorithm.Evaluate(input,ciphertext,keys.m_publicRandomVector,token);
	finish = currentDateTime();
	processingTime = finish - start;
	std::cout << "\nEvaluation time: " << processingTime << "ms" << std::endl;

	std::cout << "result (encrypted computation) = " << result << std::endl;

	start = currentDateTime();
	NativeInteger resultClear = algorithm.EvaluateClear(input,weights);
	finish = currentDateTime();
	processingTime = finish - start;
	std::cout << "\nEvaluation time (in clear): " << processingTime << "ms" << std::endl;

	std::cout << "result (plaintext computation) = " << resultClear << std::endl;

	return 0;

}
