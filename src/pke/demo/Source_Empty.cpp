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


void EvalMultBigRing();
void EvalMultSmallRing();
void EvalAutomorphism();


vector<shared_ptr<Ciphertext<ILVector2n>>> AutomorphCiphertext(vector<shared_ptr<Ciphertext<ILVector2n>>> &ciphertext, usint k);
std::shared_ptr<LPPrivateKey<ILVector2n>> AutomorphSecretkey(std::shared_ptr<LPPrivateKey<ILVector2n>> sk, usint k);

int main(int argc, char *argv[])
{
	EvalAutomorphism();
	
	std::cin.get();

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

void EvalMultSmallRing() {
	usint m = 22;
	usint p = 89; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigBinaryInteger modulusQ("72385066601");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("69414828251");
	BigBinaryInteger bigmodulus("77302754575416994210914689");
	BigBinaryInteger bigroot("76686504597021638023705542");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, p, 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;

	std::vector<usint> vectorOfInts1;
	/*for (usint i = 0; i < N; i++) {
		vectorOfInts1.push_back(1);
	}*/
	vectorOfInts1 = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	std::vector<usint> vectorOfInts2;
	/*for (usint i = 0; i < N; i++) {
		vectorOfInts2.push_back(2);
	}*/
	vectorOfInts2 = { 10,9,8,7,6,5,4,3,2,1 };
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

void EvalAutomorphism() {

	usint m = 22;
	usint p = 23;
	BigBinaryInteger modulusP(p);
	BigBinaryInteger modulusQ("12778598974616693871020696593");
	BigBinaryInteger squareRootOfRoot("12261452723167243236320113431");
	//BigBinaryInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	usint n = GetTotient(m);
	BigBinaryInteger bigmodulus("26737774526602763422133842307743584503443924104487050441559489");
	BigBinaryInteger bigroot("25833580194401688117896146800363926299361767688444709258053273");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, p, 8, stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);
	cc.Enable(LEVELEDSHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();
	//kp.secretKey->GetPrivateElement().PrintValues();

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };//packed encoding of 1:10
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, intArray1, false);
	//ciphertext.at(0)->GetElements().at(0).PrintValues();
	//ciphertext.at(0)->GetElements().at(1).PrintValues();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphed = AutomorphCiphertext(ciphertext, 7);

	//ciphertextAutomorphed.at(0)->GetElements().at(0).PrintValues();
	//ciphertextAutomorphed.at(0)->GetElements().at(1).PrintValues();

	
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphed = AutomorphSecretkey(kp.secretKey, 7);

	PackedIntPlaintextEncoding intArrayCheck;

	cc.Decrypt(skmorphed, ciphertextAutomorphed, &intArrayCheck, false);
	std::cout << intArrayCheck << std::endl;

	

	//vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedSwitched;
	////kp.secretKey->GetPrivateElement().PrintValues();
	////skmorphed->GetPrivateElement().PrintValues();

	//auto keyswitch = cc.KeySwitchGen(skmorphed, kp.secretKey);

	//auto switchedCipher = cc.KeySwitch(keyswitch, ciphertextAutomorphed.at(0));
	////switchedCipher->GetElements().at(0).PrintValues();
	////switchedCipher->GetElements().at(1).PrintValues();

	//ciphertextAutomorphedSwitched.insert(ciphertextAutomorphedSwitched.begin(), switchedCipher);

	//PackedIntPlaintextEncoding intArrayNew;

	//cc.Decrypt(skmorphed, ciphertextAutomorphedSwitched, &intArrayNew, false);

	//std::cout << intArrayNew << std::endl;

}

vector<shared_ptr<Ciphertext<ILVector2n>>> AutomorphCiphertext(vector<shared_ptr<Ciphertext<ILVector2n>>> &ciphertext, usint k) {
	vector<shared_ptr<Ciphertext<ILVector2n>>> result;
	for (usint i = 0; i < ciphertext.size(); i++) {
		auto shrCipher = ciphertext.at(i);
		shared_ptr<Ciphertext<ILVector2n>> ciphertextResult(new Ciphertext<ILVector2n>(shrCipher->GetCryptoContext()));
		std::vector<ILVector2n> morphedCipherElements(shrCipher->GetElements());
		for (usint j = 0; j < morphedCipherElements.size(); j++) {
			morphedCipherElements.at(i).SIAutomorphism(k);
		}
		ciphertextResult->SetElements(std::move(morphedCipherElements));
		result.push_back(ciphertextResult);
	}
	return result;
}

std::shared_ptr<LPPrivateKey<ILVector2n>> AutomorphSecretkey(std::shared_ptr<LPPrivateKey<ILVector2n>> sk, usint k) {
	std::shared_ptr<LPPrivateKey<ILVector2n>> morphedSK(new LPPrivateKey<ILVector2n>(sk->GetCryptoContext()));
	ILVector2n morphedSKElement(sk->GetPrivateElement());
	morphedSKElement.SIAutomorphism(k);
	morphedSK->SetPrivateElement(std::move(morphedSKElement));

	return morphedSK;
}

