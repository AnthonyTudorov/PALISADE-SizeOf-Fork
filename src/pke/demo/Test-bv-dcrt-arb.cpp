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


#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"


using namespace std;
using namespace lbcrypto;


#include <iterator>

//ILVector2n tests
void ArbBVAutomorphismPackedArray(usint i);

int main() {

	//LTVAutomorphismIntArray();
	usint m = 22;
	std::vector<usint> totientList = GetTotientList(m);

	std::cout << "\n===========BV TESTS (EVALAUTOMORPHISM-ARBITRARY)===============: " << std::endl;

	PackedIntPlaintextEncoding::Destroy();
	ArbBVAutomorphismPackedArray(totientList[3]);

	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}


void ArbBVAutomorphismPackedArray(usint i) {

	usint m = 22;

	usint init_size = 6;
	usint big_size = 14;
	usint dcrtBits = 10;

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<native_int::BinaryInteger> init_moduli(init_size);
	vector<native_int::BinaryInteger> init_rootsOfUnity(init_size);

	native_int::BinaryInteger q = FirstPrime<native_int::BinaryInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	BigBinaryInteger modulus(1);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
		modulus = modulus * BigBinaryInteger(init_moduli[i].ConvertToInt());
	}

	// populate the towers for the big modulus

	vector<native_int::BinaryInteger> init_moduli_NTT(big_size);
	vector<native_int::BinaryInteger> init_rootsOfUnity_NTT(big_size);

	q = FirstPrime<native_int::BinaryInteger>(dcrtBits, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	BigBinaryInteger modulus_NTT(1);

	for (usint i = 1; i < big_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
		modulus_NTT = modulus_NTT * BigBinaryInteger(init_moduli_NTT[i].ConvertToInt());
	}

	//shared_ptr<ILDCRTParams<BigBinaryInteger>> params(new ILDCRTParams<BigBinaryInteger>(m, init_moduli, init_rootsOfUnity));

	//usint m = 22;
	usint p = 16787;

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

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	//std::vector<usint> vectorOfInts = { 0,1,0,2,0,3,0,4,0,5 };
	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,9,10 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);
	//IntPlaintextEncoding intArray(vectorOfInts);

	if (i == 3)
		std::cout << "Input array\n\t" << intArray << std::endl;
	//std::cout << intArray << std::endl;

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	std::vector<usint> indexList = GetTotientList(m);
	indexList.erase(indexList.begin());

	auto evalKeys = cc.EvalAutomorphismKeyGen(kp.secretKey, indexList);

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


