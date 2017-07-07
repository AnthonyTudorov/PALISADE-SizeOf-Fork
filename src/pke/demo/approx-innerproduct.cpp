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
	usint p = 1093633; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigBinaryInteger modulusP(p);
	PackedIntPlaintextEncoding::SetParams(modulusP, m);

	usint batchSize = 1024;
	shared_ptr<EncodingParams> encodingParams(new EncodingParams(modulusP, PackedIntPlaintextEncoding::GetAutomorphismGenerator(modulusP), batchSize));

	BigBinaryInteger modulusQ("4809848800078200833");
	BigBinaryInteger rootOfUnity("2595390732297411718");
	BigBinaryInteger delta(modulusQ.DividedBy(modulusP));
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	auto cycloPoly = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	BigBinaryInteger EvalMultModulus("4809848800078200833");
	BigBinaryInteger EvalMultRootOfUnity("2595390732297411718");
	//BigBinaryInteger EvalMultModulus("356811923176489970264571492362373785387532289");
	//BigBinaryInteger EvalMultRootOfUnity("179395144627626817380314101250260867933074857");

	auto cycloPolyBig = GetCyclotomicPolynomial<BigBinaryVector, BigBinaryInteger>(m, EvalMultModulus);
	ChineseRemainderTransformArb<BigBinaryInteger, BigBinaryVector>::SetCylotomicPolynomial(cycloPolyBig, EvalMultModulus);

	usint relinWindow = 21;
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

	// std::cout << "Input array 1 \n\t" << intArray1 << std::endl;
	// std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext_pub;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext_priv;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext_plain;

	vector<TimingInfo>	times;
	cc->StartTiming(&times);
	cc->StopTiming();

	std::vector<usint> automorphIndexList;
	usint g = 5;
	for (usint i = 0; i < floor(log2(batchSize))-1; i++)
	{
		automorphIndexList.push_back(g);
		g = (g * g) % m;
	}
	automorphIndexList.push_back(3);
	const auto evalKeys = cc->EvalAutomorphismKeyGen(kp.secretKey, automorphIndexList);

	usint repeatCount = 10;
	for(usint n=0; n<=repeatCount; n++){
		if(n == 1)
			cc->ResumeTiming();
		ciphertext_priv = cc->Encrypt(kp.secretKey, intArray1, false, true);
		ciphertext_pub = cc->Encrypt(kp.publicKey, intArray1, false, true);
		ciphertext_plain = cc->Encrypt(kp.publicKey, intArray2, false, false);

		vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextResult;
		auto ciphertextMult = cc->EvalMultPlain(ciphertext_priv.at(0), ciphertext_plain.at(0));
		auto ciphertextInnerProd = ciphertextMult;
		for (usint i = 0; i < floor(log2(batchSize)); i++)
		{
			auto ciphertextAutomorph = cc->EvalAutomorphism(ciphertextInnerProd, automorphIndexList[i], (*evalKeys));
			ciphertextInnerProd = cc->EvalAdd(ciphertextInnerProd, ciphertextAutomorph);
		}
		// auto ciphertextInnerProd = cc->EvalSum(ciphertextMult, batchSize);
		// auto ciphertextFin = cc->GetEncryptionAlgorithm()->AddRandomNoise(ciphertextInnerProd);

		auto ciphertextFin = cc->EvalInnerProduct(ciphertext_pub.at(0), ciphertext_plain.at(0), batchSize);
		ciphertextResult.insert(ciphertextResult.begin(), ciphertextFin);
		PackedIntPlaintextEncoding intArrayNew;
		cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew, false);
		std::cout << "Actual = " << intArrayNew << std::endl;
	}
	cc->StopTiming();

	// time to assemble timing statistics
	map<OpType,TimingStatistics> stats;
	for( TimingInfo& sample : times ) {
		TimingStatistics& st = stats[ sample.operation ];
		if( st.operation == OpNOOP ) {
			st.operation = sample.operation;
			st.startup = sample.timeval;
		} else {
			st.samples++;
			st.average += sample.timeval;
			if( sample.timeval < st.min )
				st.min = sample.timeval;
			if( sample.timeval > st.max )
				st.max = sample.timeval;
		}
	}

	// read them out
	for( auto &tstat : stats ) {
		auto ts = tstat.second;
		ts.average /= ts.samples;

		cout << tstat.first << ':' << ts << endl;

		Serialized ser;
		if( ts.Serialize(&ser) == false ) {
			cout << "Cannot serialize a measurement for " << ts.operation << endl;
			return 1;
		}
	}

	return 0;
}
