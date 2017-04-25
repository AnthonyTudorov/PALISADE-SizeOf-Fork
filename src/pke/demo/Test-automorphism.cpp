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


#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"
#include <random>


using namespace std;
using namespace lbcrypto;


#include <iterator>

//ILVector2n tests
void LTVAutomorphismIntArray();
void LTVEvalAtIndexPackedArray(usint i);
void LTVAutomorphismPackedArray(usint i);
void LTVEvalSumPackedArray();
void BVAutomorphismPackedArray(usint i);
void FVAutomorphismPackedArray(usint i);

int main() {

	//LTVAutomorphismIntArray();

	std::cout << "\n===========LTV TESTS (EVALATINDEX)===============: " << std::endl;

	for (usint index = 2; index < 9; index++)
		LTVEvalAtIndexPackedArray(index);

	std::cout << "\n===========LTV TESTS (EVALAUTOMORPHISM)===============: " << std::endl;

	for (usint index = 3; index < 16; index = index + 2)
		LTVAutomorphismPackedArray(index);

	//LTVEvalSumPackedArray();

	std::cout << "\n===========BV TESTS (EVALAUTOMORPHISM)===============: " << std::endl;

	for (usint index = 3; index < 16; index = index + 2)
		BVAutomorphismPackedArray(index);

	std::cout << "\n==============FV TESTS (EVALAUTOMORPHISM)================: " << std::endl;

	for (usint index = 3; index < 16; index = index + 2)
		FVAutomorphismPackedArray(index);

	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}

void LTVAutomorphismIntArray() {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	DiscreteGaussianGenerator dgg(stdDev);

	shared_ptr<ILParams> params( new ILParams(m, q, rootOfUnity) );

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(
			params, plaintextModulus, 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 0,1,2,3,4,5,6,7 };
	//PackedIntPlaintextEncoding intArray(vectorOfInts);
	IntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	std::cout << "about to run EvalAutomorphismGen" << std::endl;

	shared_ptr<std::vector<shared_ptr<LPEvalKey<ILVector2n>>>> evalKeys =
		cc.EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, 3);

	std::cout << "just ran EvalAutomorphismGen" << std::endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> permutedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1;

	std::cout << "about to run EvalAtIndex" << std::endl;

	p1 = cc.EvalAtIndex(ciphertext[0], 3, *evalKeys);

	std::cout << "just ran EvalAtIndex" << std::endl;

	permutedCiphertext.push_back(p1);

	//PackedIntPlaintextEncoding intArrayNew;
	IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index 3 (using only odd coefficients)\n\t" << intArrayNew << std::endl;


}

void LTVEvalAtIndexPackedArray(usint i) {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	DiscreteGaussianGenerator dgg(stdDev);

	ILParams params(m, q, rootOfUnity);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(plaintextModulus, m, q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 2)
		std::cout << "Input array\n\t" << intArray << std::endl;
		//std::cout << intArray << std::endl;

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	shared_ptr<std::vector<shared_ptr<LPEvalKey<ILVector2n>>>> evalKeys =
		cc.EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, 7);

	vector<shared_ptr<Ciphertext<ILVector2n>>> permutedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1;

	p1 = cc.EvalAtIndex(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void LTVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	ILParams params(m, q, rootOfUnity);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(plaintextModulus, m, q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	shared_ptr<std::vector<shared_ptr<LPEvalKey<ILVector2n>>>> evalKeys =
		cc.EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, 7);

	vector<shared_ptr<Ciphertext<ILVector2n>>> permutedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1;

	p1 = cc.EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void LTVEvalSumPackedArray() {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	usint plaintextModulus = 97;

	float stdDev = 4;

	DiscreteGaussianGenerator dgg(stdDev);

	ILParams params(m, q, rootOfUnity);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(plaintextModulus, m, q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	shared_ptr<std::vector<shared_ptr<LPEvalKey<ILVector2n>>>> evalKeys =
		cc.EvalAutomorphismKeyGen(kp.publicKey, kp.secretKey, 7);

	vector<shared_ptr<Ciphertext<ILVector2n>>> summedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1 = cc.EvalAtIndex(ciphertext[0], 8, *evalKeys);

	shared_ptr<Ciphertext<ILVector2n>> p2 = cc.EvalAdd(ciphertext[0], p1);

	shared_ptr<Ciphertext<ILVector2n>> p3 = cc.EvalAtIndex(p2, 4, *evalKeys);

	shared_ptr<Ciphertext<ILVector2n>> p4 = cc.EvalAdd(p2, p3);

	shared_ptr<Ciphertext<ILVector2n>> p5 = cc.EvalAtIndex(p4, 2, *evalKeys);

	shared_ptr<Ciphertext<ILVector2n>> p6 = cc.EvalAdd(p4, p5);

	summedCiphertext.push_back(p6);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, summedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	//std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	std::cout << "Expected sum is 36" << std::endl;
	std::cout << intArrayNew << std::endl;

}

void BVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	usint plaintextModulus = 17;

	float stdDev = 4;

	ILParams params(m, q, rootOfUnity);

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(plaintextModulus, m, q.ToString(), RootOfUnity(m, q).ToString(), 1, stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
		//std::cout << intArray << std::endl;

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	shared_ptr<std::vector<shared_ptr<LPEvalKey<ILVector2n>>>> evalKeys =
		cc.EvalAutomorphismKeyGen(kp.secretKey, 7, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> permutedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1;

	p1 = cc.EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}

void FVAutomorphismPackedArray(usint i) {

	usint m = 16;
	BigBinaryInteger q("67108913");
	BigBinaryInteger rootOfUnity("61564");
	usint plaintextModulus = 17;
	usint relWindow = 1;
	float stdDev = 4;

	BigBinaryInteger BBIPlaintextModulus(plaintextModulus);
	BigBinaryInteger delta(q.DividedBy(BBIPlaintextModulus));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
		plaintextModulus, m, q.ToString(), rootOfUnity.ToString(),
		relWindow, stdDev, delta.ToString());

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	shared_ptr<std::vector<shared_ptr<LPEvalKey<ILVector2n>>>> evalKeys =
		cc.EvalAutomorphismKeyGen(kp.secretKey, 7, false);

	vector<shared_ptr<Ciphertext<ILVector2n>>> permutedCiphertext;

	shared_ptr<Ciphertext<ILVector2n>> p1;

	p1 = cc.EvalAutomorphism(ciphertext[0], i, *evalKeys);

	permutedCiphertext.push_back(p1);

	PackedIntPlaintextEncoding intArrayNew;
	//IntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, permutedCiphertext, &intArrayNew, false);
	//cc.Decrypt(kp.secretKey, ciphertext, &intArrayNew, false);

	std::cout << "Automorphed array - at index " << i << " (using only odd coefficients)\n\t" << intArrayNew << std::endl;

	//std::cout << intArrayNew << std::endl;

}





