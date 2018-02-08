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

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;


#include <iterator>

int main() {
	std::cout << "\n===========BFV TESTS (INNER-PRODUCT-ARBITRARY)===============: " << std::endl;

	//------------------ Setup Parameters ------------------
	usint m = 2048;
	usint phim = 1024;
	PlaintextModulus p = 1093633; // we choose s.t. 2m|p-1 to leverage CRTArb
	BigInteger modulusP(p);

	usint batchSize = 1024;
	EncodingParams encodingParams(new EncodingParamsImpl(p, batchSize, PackedEncoding::GetAutomorphismGenerator(m)));

	PackedEncoding::SetParams(m, encodingParams);

	BigInteger modulusQ("4809848800078200833");
	BigInteger rootOfUnity("2595390732297411718");
	BigInteger delta(modulusQ.DividedBy(modulusP));
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	BigInteger EvalMultModulus("1182196001696382977");
	BigInteger EvalMultRootOfUnity("983189421893510117");

	usint relinWindow = 21;
	float stdDev = 4;
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBFV(
			params, encodingParams, relinWindow, stdDev, delta.ToString(), OPTIMIZED,
			EvalMultModulus.ToString(), EvalMultRootOfUnity.ToString(), 0, 9, 1.006
		);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	//------------------------------------------------------

	// Initialize the public key containers.
	LPKeyPair<Poly> kp = cc->KeyGen();

	std::vector<uint64_t> vectorOfInts1(phim);
	std::vector<uint64_t> vectorOfInts2(phim, 1);
	for (usint i=0; i<phim; i++){
		vectorOfInts1[i] = i % 8;
	}

	Plaintext intArray1 = cc->MakePackedPlaintext(vectorOfInts1);
	Plaintext intArray2 = cc->MakePackedPlaintext(vectorOfInts2);

	// std::cout << "Input array 1 \n\t" << intArray1 << std::endl;
	// std::cout << "Input array 2 \n\t" << intArray2 << std::endl;

	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	Ciphertext<Poly> ciphertext_pub;
	Ciphertext<Poly> ciphertext_priv;
	Ciphertext<Poly> ciphertext_plain;

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
		ciphertext_priv = cc->Encrypt(kp.secretKey, intArray1);
		ciphertext_pub = cc->Encrypt(kp.publicKey, intArray1);

		//ciphertext_plain = cc->Encrypt(kp.publicKey, intArray2, false, false);

		auto ciphertextMult = cc->EvalMult(ciphertext_priv, intArray2);
		auto ciphertextInnerProd = ciphertextMult;
		for (usint i = 0; i < floor(log2(batchSize)); i++)
		{
			auto ciphertextAutomorph = cc->EvalAutomorphism(ciphertextInnerProd, automorphIndexList[i], (*evalKeys));
			ciphertextInnerProd = cc->EvalAdd(ciphertextInnerProd, ciphertextAutomorph);
		}
		// auto ciphertextInnerProd = cc->EvalSum(ciphertextMult, batchSize);
		// auto ciphertextFin = cc->GetEncryptionAlgorithm()->AddRandomNoise(ciphertextInnerProd);

		auto ciphertextResult = cc->EvalInnerProduct(ciphertext_pub, intArray2, batchSize);
		Plaintext intArrayNew;
		cc->Decrypt(kp.secretKey, ciphertextResult, &intArrayNew);
		std::cout << "Actual = " << *intArrayNew << std::endl;
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
