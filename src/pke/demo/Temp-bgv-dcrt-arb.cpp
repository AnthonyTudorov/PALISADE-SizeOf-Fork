/*
 * @file 
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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
 /*
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

*/

#include <iostream>
#include <fstream>


#include "palisade.h"

#include <random>

using namespace std;
using namespace lbcrypto;

#include <iterator>

//Poly tests
void EvalMult();
void ArbBGVAutomorphismPackedArray(usint i);
void ArbNullAutomorphismPackedArray(usint i);
void ArbBGVInnerProductPackedArray();

int main() {


	usint m = 22;
	std::vector<usint> totientList = GetTotientList(m);

	std::cout << "\n===========BGV TESTS (EVALMULT-ARBITRARY)===============: " << std::endl;
	EvalMult();

	std::cout << "\n===========BGV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;
	ArbBGVAutomorphismPackedArray(3);

	std::cout << "\n===========NULL TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;
	ArbNullAutomorphismPackedArray(3);

	std::cout << "\n===========BGV TESTS (EVALINNER-PRODUCT-ARBITRARY)===============: " << std::endl;
	ArbBGVInnerProductPackedArray();

	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}


void ArbBGVAutomorphismPackedArray(usint i) {

	usint m = 22;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<NativeInteger> init_moduli_NTT(init_size);
	vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<NativeInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	//usint m = 22;
	usint p = 89;

	BigInteger modulusP(p);

	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");

	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");

	//auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	//ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(paramsDCRT, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto p1 = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, p1, &intArrayNew);
	
	std::cout << "Input array\n\t" << intArray << std::endl;

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

}

void EvalMult() {

	usint m = 22;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<NativeInteger> init_moduli_NTT(init_size);
	vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<NativeInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	BigInteger modulus_NTT(1);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	//usint m = 22;
	usint p = 16633;

	BigInteger modulusP(p);

	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");

	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");

	//auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	//ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


	float stdDev = 4;

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(paramsDCRT, p, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<int64_t> vectorOfInts2 = { 2,3,4,4,5,6,7,8,9,101 };
	Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	auto ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	cc->EvalMultKeyGen(kp.secretKey);

	auto p1 = cc->EvalMult(ciphertext, ciphertext2);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, p1, &intArrayNew);

	std::cout << "Input array\n\t" << intArray << std::endl;

	std::cout << "Input array 2\n\t" << intArray2 << std::endl;

	std::cout << "SIMD product\n\t" << intArrayNew << std::endl;
}

void ArbNullAutomorphismPackedArray(usint i) {

	usint m = 22;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<NativeInteger> init_moduli_NTT(init_size);
	vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<NativeInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	//usint m = 22;
	usint p = 89;

	BigInteger modulusP(p);

	//BigInteger modulusQ("955263939794561");
	//BigInteger squareRootOfRoot("941018665059848");

	//BigInteger bigmodulus("80899135611688102162227204937217");
	//BigInteger bigroot("77936753846653065954043047918387");

	//auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	//ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextNull(m, p);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	Plaintext intArray = cc->MakePackedPlaintext(vectorOfInts);

	auto ciphertext = cc->Encrypt(kp.publicKey, intArray);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, indexList);

	auto p1 = cc->EvalAutomorphism(ciphertext, i, *evalKeys);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, p1, &intArrayNew);

	std::cout << "Input array\n\t" << intArray << std::endl;

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;
}

void ArbBGVInnerProductPackedArray() {

	float stdDev = 4;

	usint batchSize = 8;


	usint m = 22;
	PlaintextModulus p = 89;

	usint init_size = 7;
	usint dcrtBits = 10;
	usint dcrtBitsBig = 28;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	// populate the towers for the big modulus

	vector<NativeInteger> init_moduli_NTT(init_size);
	vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<NativeInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		auto cycloPoly = GetCyclotomicPolynomial<NativeVector>(m, q);
		ChineseRemainderTransformArb<NativeVector>::SetCylotomicPolynomial(cycloPoly, q);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	BigInteger modulusP(p);

	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGV(paramsDCRT, encodingParams, 8, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();

	std::vector<int64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;


	std::vector<int64_t> vectorOfInts2 = { 1,2,3,2,1,2,1,2,0,0 };
	Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	auto ciphertext1 = cc->Encrypt(kp.publicKey, intArray1);
	auto ciphertext2 = cc->Encrypt(kp.publicKey, intArray2);

	auto result = cc->EvalInnerProduct(ciphertext1, ciphertext2, batchSize);

	Plaintext intArrayNew;

	cc->Decrypt(kp.secretKey, result, &intArrayNew);

	std::cout << "Sum = " << intArrayNew->GetPackedValue()[0] << std::endl;

	std::cout << "All components (other slots randomized) = " << intArrayNew << std::endl;

}

