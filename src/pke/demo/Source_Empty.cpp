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
void EvalSummation();

void PerformanceTest();
void PerformanceTestV3();
void PerformanceTestV2();
void PerformanceTestV4();

vector<shared_ptr<Ciphertext<ILVector2n>>> AutomorphCiphertext(vector<shared_ptr<Ciphertext<ILVector2n>>> &ciphertext, usint k);
std::shared_ptr<LPPrivateKey<ILVector2n>> AutomorphSecretkey(std::shared_ptr<LPPrivateKey<ILVector2n>> sk, usint k);

std::vector<usint> YuriyAutomorphism(const std::vector<usint> &input, usint i);

int main(int argc, char *argv[])
{
	/*std::vector<usint> input = { 4145365, 15446096, 13914296, 5921598, 4346276, 23277173, 10116835, 5628509, 2463476, 10824166 };

	auto res = YuriyAutomorphism(input, 7);

	for (auto &x : res)
	std::cout << x << "  ";
	std::cout << std::endl;*/

	//PerformanceTestV2();

	//EvalSummation();
	//EvalMultSmallRing();
	//EvalAutomorphism();
	PerformanceTestV4();
	
	std::cout << "Press any key to continue" << std::endl;
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
	//BigBinaryInteger modulusQ("72385066601");
	BigBinaryInteger modulusQ("23");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("69414828251");
	BigBinaryInteger bigmodulus("77302754575416994210914689");
	BigBinaryInteger bigroot("76686504597021638023705542");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetPreComputedNTTDivisionModulus(m, modulusQ, bigmodulus, bigroot);
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
	/*BigBinaryInteger modulusQ("577325471560727734926295560417311036005875689");
	BigBinaryInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	BigBinaryInteger modulusQ("955263939794561");
	BigBinaryInteger squareRootOfRoot("941018665059848");
	//BigBinaryInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	usint n = GetTotient(m);
	BigBinaryInteger bigmodulus("80899135611688102162227204937217");
	BigBinaryInteger bigroot("77936753846653065954043047918387");
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

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, intArray1, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedR1 = AutomorphCiphertext(ciphertext, 7);
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphedR1 = AutomorphSecretkey(kp.secretKey, 7);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedR2 = AutomorphCiphertext(ciphertext, 5);
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphedR2 = AutomorphSecretkey(kp.secretKey, 5);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedR3 = AutomorphCiphertext(ciphertext, 3);
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphedR3 = AutomorphSecretkey(kp.secretKey, 3);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedR4 = AutomorphCiphertext(ciphertext, 9);
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphedR4 = AutomorphSecretkey(kp.secretKey, 9);

	PackedIntPlaintextEncoding intArrayCheckR1;
	PackedIntPlaintextEncoding intArrayCheckR2;
	PackedIntPlaintextEncoding intArrayCheckR3;
	PackedIntPlaintextEncoding intArrayCheckR4;

	cc.Decrypt(skmorphedR1, ciphertextAutomorphedR1, &intArrayCheckR1, false);
	std::cout << intArrayCheckR1 << std::endl;

	cc.Decrypt(skmorphedR2, ciphertextAutomorphedR2, &intArrayCheckR2, false);
	std::cout << intArrayCheckR2 << std::endl;

	cc.Decrypt(skmorphedR3, ciphertextAutomorphedR3, &intArrayCheckR3, false);
	std::cout << intArrayCheckR3 << std::endl;

	cc.Decrypt(skmorphedR4, ciphertextAutomorphedR4, &intArrayCheckR4, false);
	std::cout << intArrayCheckR4 << std::endl;
	

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedSwitched;

	auto keyswitchR1 = cc.KeySwitchGen(skmorphedR1, kp.secretKey);

	auto switchedCipherR1 = cc.KeySwitch(keyswitchR1, ciphertextAutomorphedR1.at(0));

	ciphertextAutomorphedSwitched.insert(ciphertextAutomorphedSwitched.begin(), switchedCipherR1);

	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertextAutomorphedSwitched, &intArrayNew, false);

	std::cout << intArrayNew << std::endl;

}

void EvalSummation() {

	usint m = 22;
	usint p = 23;
	BigBinaryInteger modulusP(p);
	BigBinaryInteger modulusQ("955263939794561");
	BigBinaryInteger squareRootOfRoot("941018665059848");
	usint n = GetTotient(m);
	BigBinaryInteger bigmodulus("80899135611688102162227204937217");
	BigBinaryInteger bigroot("77936753846653065954043047918387");

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

	std::vector<usint> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray1(vectorOfInts1);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext = cc.Encrypt(kp.publicKey, intArray1, false);
	
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedR1 = AutomorphCiphertext(ciphertext, 7);
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphedR1 = AutomorphSecretkey(kp.secretKey, 7);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedSwitchedR1;
	auto keyswitchR1 = cc.KeySwitchGen(skmorphedR1, kp.secretKey);
	auto switchedCipherR1 = cc.KeySwitch(keyswitchR1, ciphertextAutomorphedR1.at(0));
	ciphertextAutomorphedSwitchedR1.insert(ciphertextAutomorphedSwitchedR1.begin(), switchedCipherR1);
	auto R1 = cc.EvalAdd(ciphertext.at(0), ciphertextAutomorphedSwitchedR1.at(0));

	ciphertext.clear();
	ciphertext.insert(ciphertext.begin(), R1);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedR2 = AutomorphCiphertext(ciphertext, 5);
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphedR2 = AutomorphSecretkey(kp.secretKey, 5);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedSwitchedR2;
	auto keyswitchR2 = cc.KeySwitchGen(skmorphedR2, kp.secretKey);
	auto switchedCipherR2 = cc.KeySwitch(keyswitchR2, ciphertextAutomorphedR2.at(0));
	ciphertextAutomorphedSwitchedR2.insert(ciphertextAutomorphedSwitchedR2.begin(), switchedCipherR2);
	auto R2 = cc.EvalAdd(ciphertext.at(0), ciphertextAutomorphedSwitchedR2.at(0));

	ciphertext.clear();
	ciphertext.insert(ciphertext.begin(), R2);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedR3 = AutomorphCiphertext(ciphertext, 3);
	std::shared_ptr<LPPrivateKey<ILVector2n>> skmorphedR3 = AutomorphSecretkey(kp.secretKey, 3);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextAutomorphedSwitchedR3;
	auto keyswitchR3 = cc.KeySwitchGen(skmorphedR3, kp.secretKey);
	auto switchedCipherR3 = cc.KeySwitch(keyswitchR3, ciphertextAutomorphedR3.at(0));
	ciphertextAutomorphedSwitchedR3.insert(ciphertextAutomorphedSwitchedR3.begin(), switchedCipherR3);
	auto R3 = cc.EvalAdd(ciphertext.at(0), ciphertextAutomorphedSwitchedR3.at(0));

	ciphertext.clear();
	ciphertext.insert(ciphertext.begin(), R3);


	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << intArrayNew << std::endl;


}

vector<shared_ptr<Ciphertext<ILVector2n>>> AutomorphCiphertext(vector<shared_ptr<Ciphertext<ILVector2n>>> &ciphertext, usint k) {
	std::vector<shared_ptr<Ciphertext<ILVector2n>>> result;
	for (usint i = 0; i < ciphertext.size(); i++) {
		auto shrCipher = ciphertext.at(i);
		shared_ptr<Ciphertext<ILVector2n>> ciphertextResult(new Ciphertext<ILVector2n>(shrCipher->GetCryptoContext()));
		std::vector<ILVector2n> morphedCipherElements;
		for (usint elCounter = 0; elCounter < shrCipher->GetElements().size(); elCounter++) {
			ILVector2n temp(shrCipher->GetElements().at(elCounter));
			temp = temp.AutomorphismTransform(k);
			morphedCipherElements.push_back(std::move(temp));
		}

		ciphertextResult->SetElements(std::move(morphedCipherElements));
		result.push_back(std::move(ciphertextResult));
	}

	return result;
}

std::shared_ptr<LPPrivateKey<ILVector2n>> AutomorphSecretkey(std::shared_ptr<LPPrivateKey<ILVector2n>> sk, usint k) {
	std::shared_ptr<LPPrivateKey<ILVector2n>> morphedSK(new LPPrivateKey<ILVector2n>(sk->GetCryptoContext()));
	ILVector2n morphedSKElement(sk->GetPrivateElement());
	morphedSKElement = morphedSKElement.AutomorphismTransform(k);
	morphedSK->SetPrivateElement(std::move(morphedSKElement));

	return morphedSK;
}

void PerformanceTest() {

	usint m = 8422;
	BigBinaryInteger modulus("1194825523642870048326524785366004369"); //120 bits
	BigBinaryInteger squareRootOfRoot("1125399230456375417724134273593267324");
	BigBinaryInteger bigModulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041"); //260 bits
	BigBinaryInteger bigRoot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");
	BigBinaryInteger bigModulusNTTDivision("22852932273529643486316954447175244494414503554339459946903988163765274935297");//254 bits
	BigBinaryInteger bigRootNTTDivision("166896813997959873062972192819860531324067319379918385803279340301727857067");
	usint n = GetTotient(m);
	usint m_nttDivisionDim = 2 * std::pow(2, ceil(log2(m-n)));
	//BigBinaryInteger bigRootNTTDivision = RootOfUnity(m_nttDivisionDim, bigModulusNTTDivision);
	//std::cout << bigRootNTTDivision << std::endl;
	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetPreComputedNTTDivisionModulus(m, modulus, bigModulusNTTDivision, bigRootNTTDivision);

	BigBinaryVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };
	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);


	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	double start, stop, diff;

	start = currentDateTime();

	INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Forward Transform computation time is :\t" << diff << std::endl;

	start = currentDateTime();

	inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Inverse Transform computation time is :\t" << diff << std::endl;

	std::cout << inputCheck << std::endl;
}

void PerformanceTestV3() {

	usint m = 22;
	BigBinaryInteger modulus("89"); //120 bits
	BigBinaryInteger squareRootOfRoot("84");
	BigBinaryInteger bigModulus("4072961"); //260 bits
	BigBinaryInteger bigRoot("4063975");
	BigBinaryInteger bigModulusNTTDivision("4164673"); //260 bits
	BigBinaryInteger bigRootNTTDivision("3987663");

	usint n = GetTotient(m);

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetPreComputedNTTDivisionModulus(m, modulus, bigModulusNTTDivision, bigRootNTTDivision);

	BigBinaryVector input(n, modulus);
	input = { 1,2,3,4,5,6,7,8,9,10 };
	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);


	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	double start, stop, diff;

	start = currentDateTime();

	INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Forward Transform computation time is :\t" << diff << std::endl;

	start = currentDateTime();

	inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Inverse Transform computation time is :\t" << diff << std::endl;

	std::cout << inputCheck << std::endl;
}



void PerformanceTestV2() {

	usint m = 9742;
	usint n = GetTotient(m);
	BigBinaryInteger modulus("1329227995784915872903807060281374689");
	BigBinaryInteger squareRootOfRoot("1103835257645791936030700335506173789");

	BigBinaryInteger bigModulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041");
	BigBinaryInteger bigRoot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);

	BigBinaryVector input(n, modulus);
	DiscreteUniformGenerator dug;
	dug.SetModulus(modulus);

	input = dug.GenerateVector(n);

	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);

	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	double start, stop, diff;

	start = currentDateTime();

	INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Forward Transform computation time is :\t" << diff << std::endl;

	start = currentDateTime();

	inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Inverse Transform computation time is :\t" << diff << std::endl;

	//std::cout << inputCheck << std::endl;
}

void PerformanceTestV4() {

	usint m = 8422;
	BigBinaryInteger modulus("1194825523642870048326524785366004369"); //120 bits
	BigBinaryInteger squareRootOfRoot("1125399230456375417724134273593267324");
	BigBinaryInteger bigModulus("1852673427797059126777135760139006525652319754650249024631321344126610076631041"); //260 bits
	BigBinaryInteger bigRoot("1011857408422309039039556907195908859561535234649870814154019834362746408101010");
	BigBinaryInteger bigModulusNTTDivision("22852932273529643486316954447175244494414503554339459946903988163765274935297");//254 bits
	BigBinaryInteger bigRootNTTDivision("166896813997959873062972192819860531324067319379918385803279340301727857067");
	usint n = GetTotient(m);
	usint m_nttDivisionDim = 2 * std::pow(2, ceil(log2(m - n)));
	//BigBinaryInteger bigRootNTTDivision = RootOfUnity(m_nttDivisionDim, bigModulusNTTDivision);
	//std::cout << bigRootNTTDivision << std::endl;
	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulus);

	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetPreComputedNTTDivisionModulus(m, modulus, bigModulusNTTDivision, bigRootNTTDivision);

	//BigBinaryVector input(n, modulus);
	//input = { 1,2,3,4,5,6,7,8,9,10 };

	BigBinaryVector input(n, modulus);
	DiscreteUniformGenerator dug;
	dug.SetModulus(modulus);

	input = dug.GenerateVector(n);

	auto INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);


	auto inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	double start, stop, diff;

	start = currentDateTime();

	INPUT = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().ForwardTransform(input, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Forward Transform computation time is :\t" << diff << std::endl;

	start = currentDateTime();

	inputCheck = ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().InverseTransform(INPUT, squareRootOfRoot, bigModulus, bigRoot, m);

	stop = currentDateTime();

	diff = stop - start;

	std::cout << "Inverse Transform computation time is :\t" << diff << std::endl;

	//std::cout << inputCheck << std::endl;
}



std::vector<usint> YuriyAutomorphism(const std::vector<usint>& input, usint i)
{
	usint m = 22;
	usint n = 10;

	std::vector<usint> result(n, 0);

	std::vector<usint> totientList = GetTotientList(m);
	usint totientIndex = totientList[i];

	for (usint k = 0; k < n; k++)
	{
		//which power of primitive root unity we should switch to
		usint newOmegaPower = (totientList[k] * totientIndex) % m;
		//std::cout << "omegaPower = " << newOmegaPower << std::endl;

		//index in the totient list corresponding to the new omega power
		size_t p = 0;

		for (p = 0; p < n; p++) {
			if (newOmegaPower == totientList[p]) {
				break;
			}
		}
		//std::cout << "p = " << p << std::endl;

		result.at(p) = input.at(k);
	}

	return result;
}

