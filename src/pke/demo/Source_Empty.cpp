//Hi Level Execution/Demonstration
/*
 * @file Source_json.cpp - PALISADE library.
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <chrono>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


int main(int argc, char *argv[])
{
	
	usint m = 8422;
	BigBinaryInteger modulus("619578785044668429129510602549015713");//find a modulus that has 2*8422 root of unity and is 120 bit long
	BigBinaryInteger squareRootOfRoot("204851043665385327685783246012876507");
	usint n = GetTotient(m);

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);
	BigBinaryInteger nttmodulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041");//260 bit long
	BigBinaryInteger nttroot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetPreComputedNTTModulus(m, modulus, nttmodulus, nttroot);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);

	BigBinaryVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };

	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, nttmodulus, nttroot, m);

	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, nttmodulus, nttroot, m);

	double diff, start, finish;

	start = currentDateTime();

	INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, nttmodulus, nttroot, m);

	finish = currentDateTime();

	diff = finish - start;

	std::cout << "Forward Transform using precomputation is\t" << diff << std::endl;

	start = currentDateTime();

	inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, nttmodulus, nttroot, m);

	finish = currentDateTime();

	diff = finish - start;

	std::cout << "Inverse Transform using precomputation is\t" << diff << std::endl;


	system("pause");

	return 0;
}

void EvalMultBigRing() {
	usint m = 8422;
	usint N = GetTotient(m);
	usint p = 84221; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigBinaryInteger modulusQ("619578785044668429129510602549015713");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("204851043665385327685783246012876507");
	BigBinaryInteger bigmodulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041");
	BigBinaryInteger bigroot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, p, 8, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;

	std::vector<usint> vectorOfInts1;
	for (usint i = 0; i < N; i++) {
		vectorOfInts1.push_back(1);
	}
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2;
	for (usint i = 0; i < N; i++) {
		vectorOfInts2.push_back(2);
	}
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	ciphertext1 = cc.Encrypt(kp.publicKey, intArray1, false);
	ciphertext2 = cc.Encrypt(kp.publicKey, intArray2, false);

	cc.EvalMultKeyGen(kp.secretKey);

	auto ciphertextMult = cc.EvalMult(ciphertext1.at(0), ciphertext2.at(0));
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextMult);
	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);

	std::cout << intArrayNew << std::endl;
}


