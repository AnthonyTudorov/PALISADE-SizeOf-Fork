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
	usint m = 1051;
	usint p = 4304897; // we choose s.t. 2m|p-1 to leverage CRTArb

	BigBinaryInteger modulusQ("277982008135681");
	BigBinaryInteger modulusP(p);
	BigBinaryInteger rootOfUnity("24403853649624");

	BigBinaryInteger bigmodulus("277982008135681");
	BigBinaryInteger bigroot("27937174802548");

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	float stdDev = 4;

	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity, bigmodulus, bigroot));

	BigBinaryInteger bigEvalMultModulus("5316911983139663491615228241270218753");
	BigBinaryInteger bigEvalMultRootOfUnity("358051043311792747609278323720231473");
	BigBinaryInteger bigEvalMultModulusAlt("5316911983139663491615228241270218753");
	BigBinaryInteger bigEvalMultRootOfUnityAlt("1719066664281287604371558126323533989");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, bigEvalMultModulus);
	//ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::GetInstance().PreCompute(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, bigEvalMultModulus);

	usint batchSize = 1024;
	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));


	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));

	shared_ptr<CryptoContext<ILVector2n>> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(params, encodingParams, 8, stdDev, delta.ToString(), OPTIMIZED,
		bigEvalMultModulus.ToString(), bigEvalMultRootOfUnity.ToString(), 1, 9, 1.006, bigEvalMultModulusAlt.ToString(), bigEvalMultRootOfUnityAlt.ToString());

	//BigBinaryInteger modulusQ("955263939794561");
	//BigBinaryInteger squareRootOfRoot("941018665059848");

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	//------------------------------------------------------

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc->KeyGen();

	std::vector<usint> vectorOfInts1(m-1);
	std::vector<usint> vectorOfInts2(m-1, 1);
	for (usint i=0; i<m-1; i++){
		vectorOfInts1[i] = i % 8;
	}

	PackedIntPlaintextEncoding intArray1(vectorOfInts1);
	PackedIntPlaintextEncoding intArray2(vectorOfInts2);

	shared_ptr<ILVector2n> plaintext(new ILVector2n(params, EVALUATION, true));
	for(usint i=0; i<(m-1); i++){
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
	auto ciphertextMult = cc->EvalMultPlain(ciphertext.at(0), ciphertext2.at(0));
	auto ciphertextInnerProd = cc->EvalSum(ciphertextMult, batchSize);
	auto ciphertextInnerProd2 = cc->EvalInnerProduct(ciphertext.at(0), ciphertext2.at(0), batchSize);
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextInnerProd);
	PackedIntPlaintextEncoding intArrayNew;
	cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);
	std::cout << "Actual = " << intArrayNew << std::endl;

	/*
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;
	auto ciphertextMult = cc.EvalMultPlain(ciphertext.at(0), plaintext);
	auto ciphertextInnerProd = cc.EvalSum(ciphertextMult, batchSize);
	auto ciphertextFin = cc.GetEncryptionAlgorithm()->AddRandomNoise(ciphertextInnerProd);
	ciphertextResult.insert(ciphertextResult.begin(), ciphertextFin);
	PackedIntPlaintextEncoding intArrayNew;

	cc.Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);

	std::cout << "Sum = " << intArrayNew[0] << std::endl;

	std::cout << "Actual = " << intArrayNew << std::endl;
	*/
	return 0;
}
