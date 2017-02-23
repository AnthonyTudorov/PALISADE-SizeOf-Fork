/*
 * SHE.cpp
 *
 *  Created on: Feb 18, 2017
 *      Author: gerardryan
 */

#define _USE_MATH_DEFINES
#include "benchmark/benchmark_api.h"


#include <iostream>
#include <fstream>
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

string parms[] = { "Null", "Null2", "LTV5", "FV1", "FV2" };

static std::vector<uint32_t> makeVector(int siz, int ptmi) {
	std::vector<uint32_t>			elem;

	for( int i=0; i<siz; i++ )
		elem.push_back(i%ptmi);

	return std::move(elem);
}

static void setup_SHE(CryptoContext<ILVector2n>& cc, shared_ptr<Ciphertext<ILVector2n>>& ct1, shared_ptr<Ciphertext<ILVector2n>>& ct2) {
	int nel = cc.GetElementParams()->GetCyclotomicOrder()/2;
	const BigBinaryInteger& ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
	uint32_t ptmi = ptm.ConvertToInt();

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	IntPlaintextEncoding p1( makeVector(nel, ptmi) );
	IntPlaintextEncoding p2( makeVector(nel, ptmi) );

	vector<shared_ptr<Ciphertext<ILVector2n>>> ct1V = cc.Encrypt(kp.publicKey, p1, false);
	vector<shared_ptr<Ciphertext<ILVector2n>>> ct2V = cc.Encrypt(kp.publicKey, p2, false);

	cc.EvalMultKeyGen(kp.secretKey);

	ct1 = ct1V[0];
	ct2 = ct2V[0];
}

void BM_evalAdd_SHE(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	shared_ptr<Ciphertext<ILVector2n>> ct1, ct2;

	if( state.thread_index == 0 ) {
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		setup_SHE(cc, ct1, ct2);
	}

	while (state.KeepRunning()) {
		shared_ptr<Ciphertext<ILVector2n>> ctP = cc.EvalAdd(ct1, ct2);
	}

//	ChineseRemainderTransformFTT::GetInstance().Destroy();
//	NumberTheoreticTransform::GetInstance().Destroy();
//	ILVector2n::DestroyPreComputedSamples();
}

BENCHMARK(BM_evalAdd_SHE)->ArgName(parms[0])->Arg(0);
BENCHMARK(BM_evalAdd_SHE)->ArgName(parms[1])->Arg(1);
BENCHMARK(BM_evalAdd_SHE)->ArgName(parms[2])->Arg(2);
BENCHMARK(BM_evalAdd_SHE)->ArgName(parms[3])->Arg(3);
BENCHMARK(BM_evalAdd_SHE)->ArgName(parms[4])->Arg(4);

void BM_evalMult_SHE(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	shared_ptr<Ciphertext<ILVector2n>> ct1, ct2;

	if( state.thread_index == 0 ) {
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		setup_SHE(cc, ct1, ct2);
	}

	while (state.KeepRunning()) {
		shared_ptr<Ciphertext<ILVector2n>> ctP = cc.EvalMult(ct1, ct2);
	}
}

BENCHMARK(BM_evalMult_SHE)->ArgName(parms[0])->Arg(0);
BENCHMARK(BM_evalMult_SHE)->ArgName(parms[1])->Arg(1);
BENCHMARK(BM_evalMult_SHE)->ArgName(parms[2])->Arg(2);
BENCHMARK(BM_evalMult_SHE)->ArgName(parms[3])->Arg(3);
BENCHMARK(BM_evalMult_SHE)->ArgName(parms[4])->Arg(4);

void BM_baseDecompose_SHE(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	shared_ptr<Ciphertext<ILVector2n>> ct1, ct2;

	if( state.thread_index == 0 ) {
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		setup_SHE(cc, ct1, ct2);
	}

	while (state.KeepRunning()) {
		vector<ILVector2n> ctP = ct1->GetElements()[0].BaseDecompose(8);
	}
}

//BENCHMARK(BM_baseDecompose_SHE)->ArgName(parms[0])->Arg(0);
//BENCHMARK(BM_baseDecompose_SHE)->ArgName(parms[1])->Arg(1);
BENCHMARK(BM_baseDecompose_SHE)->ArgName(parms[2])->Arg(2);
BENCHMARK(BM_baseDecompose_SHE)->ArgName(parms[3])->Arg(3);
BENCHMARK(BM_baseDecompose_SHE)->ArgName(parms[4])->Arg(4);

//execute the benchmarks
BENCHMARK_MAIN()



