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

#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;


#include <iterator>

void ArbLTVEvalSumPackedArray();
void ArbBVEvalSumPackedArray();

int main() {

	usint m = 22;

	//LTVAutomorphismIntArray();

	std::cout << "\n===========LTV TESTS (EVALSUM-ARBITRARY)===============: " << std::endl;

	ArbLTVEvalSumPackedArray();

	std::cout << "\n===========BV TESTS (EVALSUM-ARBITRARY)===============: " << std::endl;

	ArbBVEvalSumPackedArray();


	std::cout << "Please press any key to continue..." << std::endl;

	cin.get();
	return 0;
}

void ArbBVEvalSumPackedArray() {

	usint m = 22;
	usint p = 89;
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

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP,PackedIntPlaintextEncoding::GetInitRoot(),batchSize));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(params, encodingParams, 8, stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	cc.EvalSumKeyGen(kp.secretKey);

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc.EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

}


void ArbLTVEvalSumPackedArray() {

	usint m = 22;
	usint p = 89;
	BigBinaryInteger modulusP(p);
	/*BigBinaryInteger modulusQ("577325471560727734926295560417311036005875689");
	BigBinaryInteger squareRootOfRoot("576597741275581172514290864170674379520285921");*/
	//BigBinaryInteger modulusQ("955263939794561");
	//BigBinaryInteger squareRootOfRoot("941018665059848");
	BigBinaryInteger modulusQ("1152921504606847009");
	BigBinaryInteger squareRootOfRoot("1147559132892757400");

	//BigBinaryInteger squareRootOfRoot = RootOfUnity(2*m,modulusQ);
	//std::cout << squareRootOfRoot << std::endl;
	usint n = GetTotient(m);
	//BigBinaryInteger bigmodulus("80899135611688102162227204937217");
	//BigBinaryInteger bigroot("77936753846653065954043047918387");
	BigBinaryInteger bigmodulus("1361129467683753853853498429727072847489");
	BigBinaryInteger bigroot("574170933302565148884487552139817611806");
	//std::cout << bigroot << std::endl;

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	float stdDev = 4;

	usint batchSize = 8;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetInitRoot(), batchSize));

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextLTV(params, encodingParams, 16, stdDev);

	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	std::vector<usint> vectorOfInts = { 1,2,3,4,5,6,7,8,0,0 };
	PackedIntPlaintextEncoding intArray(vectorOfInts);

	std::cout << "Input array\n\t" << intArray << std::endl;

	cc.EvalSumKeyGen(kp.secretKey,kp.publicKey);

	ciphertext = cc.Encrypt(kp.publicKey, intArray, false);

	auto ciphertext1 = cc.EvalSum(ciphertext[0], batchSize);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextSum;

	ciphertextSum.push_back(ciphertext1);

	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertextSum, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

}

