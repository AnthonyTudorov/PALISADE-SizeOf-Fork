/*
Encrypted-NN: Approximate Inner Product Demo

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

Description:
This code calculated an approximate inner product over a batch of ciphertexts.

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

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

int main() {
	std::cout << "\n===========FV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;

	//------------------ Setup Parameters ------------------
	usint m = 2048;
	usint phim = 1024;
	usint p = 301057; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigBinaryInteger modulusP(p);
	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 1024;
	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigBinaryInteger modulusQ("1293029969231873");
	BigBinaryInteger rootOfUnity("1062294960958486");
	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	BigBinaryInteger EvalMultModulus("5316911983139663491615228241270218753");
	BigBinaryInteger EvalMultRootOfUnity("358051043311792747609278323720231473");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, EvalMultModulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, EvalMultModulus);

	usint relinWindow = 8;
	float stdDev = 4;
	shared_ptr<CryptoContext<ILVector2n>> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
			params, encodingParams, relinWindow, stdDev, delta.ToString(), OPTIMIZED,
			EvalMultModulus.ToString(), EvalMultRootOfUnity.ToString(), 0, 9, 1.006
		);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	//------------------------------------------------------

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc->KeyGen();

	std::vector<usint> vectorOfInts1(phim);
	std::vector<usint> vectorOfInts2(phim, 1);
	for (usint i=0; i<phim; i++){
		vectorOfInts1[i] = i % 8;
	}

	PackedIntPlaintextEncoding intArray1(vectorOfInts1);
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	shared_ptr<ILVector2n> plaintext(new ILVector2n(params, EVALUATION, true));
	for(usint i=0; i<phim; i++){
		plaintext->SetValAtIndex(i, BigBinaryInteger(vectorOfInts2[i]));
	}

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;

	ciphertext = cc->Encrypt(kp.publicKey, intArray1, false, true);
	ciphertext2 = cc->Encrypt(kp.publicKey, intArray2, false, false);

	std::cout << "Input array 1 \n\t" << intArray1 << std::endl;
	std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;
	// auto ciphertextMult = cc->EvalMultPlain(ciphertext.at(0), ciphertext2.at(0));
	// auto ciphertextInnerProd = cc->EvalSum(ciphertextMult, batchSize);
	auto ciphertextInnerProd = cc->EvalInnerProduct(ciphertext.at(0), ciphertext2.at(0), batchSize);
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextInnerProd);
	PackedIntPlaintextEncoding intArrayNew;
	cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);
	std::cout << "Actual = " << intArrayNew << std::endl;

	return 0;
}
