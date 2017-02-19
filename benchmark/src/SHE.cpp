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

string parms[] = { "Null", "Null2", "LTV5", "StSt6", "FV2" };

static void CustomArguments(benchmark::internal::Benchmark* b) {
	  for (int i = 0; i < (sizeof(parms)/sizeof(parms[0])); ++i)
		  b->Arg(i);
	}

static std::vector<uint32_t> makeVector(int siz, int ptmi) {
	std::vector<uint32_t>			elem;

	for( int i=0; i<siz; i++ )
		elem.push_back(i%ptmi);

	return std::move(elem);
}

static void doEvalAdd(CryptoContext<ILVector2n>& cc, shared_ptr<Ciphertext<ILVector2n>> ct1, shared_ptr<Ciphertext<ILVector2n>> ct2) {
	shared_ptr<Ciphertext<ILVector2n>> ctP = cc.EvalAdd(ct1, ct2);
}

static void doEvalMult(CryptoContext<ILVector2n>& cc, shared_ptr<Ciphertext<ILVector2n>> ct1, shared_ptr<Ciphertext<ILVector2n>> ct2) {
	shared_ptr<Ciphertext<ILVector2n>> ctP = cc.EvalMult(ct1, ct2);
}

typedef void (*SHEfp)(CryptoContext<ILVector2n>& cc, shared_ptr<Ciphertext<ILVector2n>> ct1, shared_ptr<Ciphertext<ILVector2n>> ct2);


static void eval_LATTICE(CryptoContext<ILVector2n>& cc, SHEfp f) {	// function
	int nel = cc.GetElementParams()->GetCyclotomicOrder()/2;
	const BigBinaryInteger& ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
	uint32_t ptmi = ptm.ConvertToInt();

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	IntPlaintextEncoding p1( makeVector(nel, ptmi) );
	IntPlaintextEncoding p2( makeVector(nel, ptmi) );

	vector<shared_ptr<Ciphertext<ILVector2n>>> ct1 = cc.Encrypt(kp.publicKey, p1, false);
	vector<shared_ptr<Ciphertext<ILVector2n>>> ct2 = cc.Encrypt(kp.publicKey, p2, false);

	(*f)(cc, ct1[0], ct2[0]);
}

void BM_evalAdd_LATTICE(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;

	if( state.thread_index == 0 ) {
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);
	}

	while (state.KeepRunning()) {
		eval_LATTICE(cc, doEvalAdd);		// note even with -O3 it appears
		// this is not optimized out
		// though check with your compiler
	}

//	ChineseRemainderTransformFTT::GetInstance().Destroy();
//	NumberTheoreticTransform::GetInstance().Destroy();
//	ILVector2n::DestroyPreComputedSamples();
}

BENCHMARK(BM_evalAdd_LATTICE)->Apply(CustomArguments);;

void BM_evaMult_LATTICE(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;

	if( state.thread_index == 0 ) {
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);
	}

	while (state.KeepRunning()) {
		eval_LATTICE(cc, doEvalMult);		// note even with -O3 it appears
		// this is not optimized out
		// though check with your compiler
	}

//	ChineseRemainderTransformFTT::GetInstance().Destroy();
//	NumberTheoreticTransform::GetInstance().Destroy();
//	ILVector2n::DestroyPreComputedSamples();
}

BENCHMARK(BM_evaMult_LATTICE)->Apply(CustomArguments);

//execute the benchmarks
BENCHMARK_MAIN()



