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


void EvalMultSmallRing();
void SearchAttributeExample();
vector<shared_ptr<Ciphertext<ILVector2n>>> XOR(const shared_ptr<Ciphertext<ILVector2n>> ct1, const shared_ptr<Ciphertext<ILVector2n>> ct2);
shared_ptr<Ciphertext<ILVector2n>> Project(shared_ptr<Ciphertext<ILVector2n>> cipher, usint idx, shared_ptr<LPPublicKey<ILVector2n>> publicKey);

vector<shared_ptr<Ciphertext<ILVector2n>>> AutomorphCiphertext(vector<shared_ptr<Ciphertext<ILVector2n>>> &ciphertext, usint k);
std::shared_ptr<LPPrivateKey<ILVector2n>> AutomorphSecretkey(std::shared_ptr<LPPrivateKey<ILVector2n>> sk, usint k);

void EvalAutomorphism();
void EvalSummation();

int main(int argc, char *argv[])
{
	
	//SearchAttributeExample();
	EvalAutomorphism();
	
	std::cout << "Press any key to continue" << std::endl;
	std::cin.get();

	return 0;
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


void SearchAttributeExample()
{
	usint m = 22;
	usint p = 89;
	BigBinaryInteger modulusP(p);

	BigBinaryInteger modulusQ("955263939794561");
	BigBinaryInteger squareRootOfRoot("941018665059848");

	BigBinaryInteger bigmodulus("80899135611688102162227204937217");
	BigBinaryInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	cc.EvalMultKeyGen(kp.secretKey);

	cc.EvalSumKeyGen(kp.secretKey);

	std::vector<usint> vectorOfInts = {1,0,1,0};
	PackedIntPlaintextEncoding intArrayTemplate(vectorOfInts);

	//case of matching attribute
	std::vector<usint> vectorOfIntsAttribute0 = { 1,0,1,0 };
	PackedIntPlaintextEncoding intArrayAttribute0(vectorOfIntsAttribute0);

	//case of non-matching attribute
	std::vector<usint> vectorOfIntsAttribute1 = { 0,1,0,0 };
	PackedIntPlaintextEncoding intArrayAttribute1(vectorOfIntsAttribute1);

	auto ciphertextTemplate = cc.Encrypt(kp.publicKey, intArrayTemplate, false);

	auto ciphertextAttribute0 = cc.Encrypt(kp.publicKey, intArrayAttribute0, false);

	auto ciphertextAttribute1 = cc.Encrypt(kp.publicKey, intArrayAttribute1, false);

	//verify XOR operation
	auto xorAttr0 = XOR(ciphertextAttribute0[0], ciphertextTemplate[0]);
	auto xorAttr1 = XOR(ciphertextAttribute1[0], ciphertextTemplate[0]);


	auto AttrSearch0 = cc.EvalSum(xorAttr0[0], batchSize);
	auto AttrSearch1 = cc.EvalSum(xorAttr1[0], batchSize);
	
	auto AttrProject0 = Project(AttrSearch0, 0, kp.publicKey);
	auto AttrProject1 = Project(AttrSearch1, 0, kp.publicKey);

	BigBinaryInteger pGen(cc.GetCryptoParameters()->GetEncodingParams()->GetPlaintextGenerator());
	auto autoMorphIdx = pGen.ModExp(BigBinaryInteger(4),BigBinaryInteger(m));
	
	auto AttrRotate1 =  cc.EvalAutomorphism(AttrProject1, autoMorphIdx.ConvertToInt(), cc.GetEvalSumKey());

	
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextSum;

	ciphertextSum.push_back(AttrRotate1);

	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);
}

vector<shared_ptr<Ciphertext<ILVector2n>>> XOR(const shared_ptr<Ciphertext<ILVector2n>> ct1, const shared_ptr<Ciphertext<ILVector2n>> ct2)
{
	vector<shared_ptr<Ciphertext<ILVector2n>>> result;
	
	auto ek = ct1->GetCryptoContext().GetEvalMultKey();

	auto multct12 = ct1->GetCryptoContext().EvalMult(ct1, ct2, ek);

	shared_ptr<Ciphertext<ILVector2n>> doublect12(new Ciphertext<ILVector2n>(ct1->GetCryptoContext()));

	std::vector<ILVector2n> doubleElements;

	for (usint i = 0; i < multct12->GetElements().size();i++) {
		ILVector2n temp(multct12->GetElements().at(i));

		temp = temp*BigBinaryInteger::TWO;

		doubleElements.push_back(std::move(temp));
	}

	doublect12->SetElements(doubleElements);

	auto ctAdd = ct1->GetCryptoContext().EvalAdd(ct1, ct2);

	auto ctFinal = ct1->GetCryptoContext().EvalSub(ctAdd, doublect12);

	result.insert(result.begin(), ctFinal);
	
	return result;
}

shared_ptr<Ciphertext<ILVector2n>> Project(shared_ptr<Ciphertext<ILVector2n>> cipher, usint idx, shared_ptr<LPPublicKey<ILVector2n>> publicKey)
{

	auto cc = publicKey->GetCryptoContext();

	usint rDim = cc.GetCryptoParameters()->GetElementParams()->GetRingDimension();

	std::vector<usint> projectVector(rDim, 0);

	projectVector.at(idx) = 1;

	PackedIntPlaintextEncoding projEncoding(projectVector);

	auto cipherProject = cc.Encrypt(publicKey, projEncoding, false,false);

	auto ek = cc.GetEvalMultKey();

	auto result = cc.EvalMult(cipher, cipherProject[0],ek);

	return result;
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