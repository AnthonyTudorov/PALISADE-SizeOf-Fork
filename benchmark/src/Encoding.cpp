/*
 * SHE.cpp
 *
 *  Created on: Feb 18, 2017
 *      Author: gerardryan
 */

#define _USE_MATH_DEFINES
#include "benchmark/benchmark_api.h"

bool runOnlyOnce = true;

#include <iostream>
#include <fstream>
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "EncryptHelper.h"

using namespace std;
using namespace lbcrypto;

static void initializeBytes(int cyclotomicOrder, const BigBinaryInteger& ptm,
		BytePlaintextEncoding& plaintextShort,
		BytePlaintextEncoding& plaintextFull,
		BytePlaintextEncoding& plaintextLong) {
	size_t strSize = plaintextShort.GetChunksize(cyclotomicOrder, ptm);

	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};

	string shortStr(strSize/2,0);
	std::generate_n(shortStr.begin(), strSize/2, randchar);
	plaintextShort = shortStr;

	string fullStr(strSize,0);
	std::generate_n(fullStr.begin(), strSize, randchar);
	plaintextFull = fullStr;

	string longStr(strSize*2,0);
	std::generate_n(longStr.begin(), strSize*2, randchar);
	plaintextLong = longStr;
}


static void setup_Encoding(CryptoContext<ILVector2n>& cc,
		IntPlaintextEncoding& plaintextInt,
		PackedIntPlaintextEncoding& plaintextPacked,
		BytePlaintextEncoding& plaintextShort,
		BytePlaintextEncoding& plaintextFull,
		BytePlaintextEncoding& plaintextLong) {
	int nel = cc.GetElementParams()->GetCyclotomicOrder()/2;
	const BigBinaryInteger& ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
	uint32_t ptmi = ptm.ConvertToInt();

	vector<uint32_t> intvec;
	for( int ii=0; ii<nel; ii++)
		intvec.push_back( rand() % ptmi );
	plaintextInt = intvec;
	plaintextPacked = intvec;

	initializeBytes(nel*2, ptm, plaintextShort, plaintextFull, plaintextLong);
}

void BM_encoding_Int(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	IntPlaintextEncoding plaintextInt;
	PackedIntPlaintextEncoding plaintextPacked;
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;
	BigBinaryInteger ptm;
	usint ptmi;
	size_t chunkSize;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = plaintextInt.GetChunksize(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);
		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		ILVector2n pt(cc.GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		plaintextInt.Encode(ptm, &pt, 0, chunkSize);
	}

	//	ChineseRemainderTransformFTT<BigBinaryInteger,BigBinaryVector>::GetInstance().Destroy();
	//	NumberTheoreticTransform::GetInstance().Destroy();
	//	ILVector2n::DestroyPreComputedSamples();
}

BENCHMARK_PARMS(BM_encoding_Int)

void BM_encoding_PackedInt(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	IntPlaintextEncoding plaintextInt;
	PackedIntPlaintextEncoding plaintextPacked;
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;
	BigBinaryInteger ptm;
	usint ptmi;
	size_t chunkSize;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);
		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = plaintextPacked.GetChunksize(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);
		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		ILVector2n pt(cc.GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		try {
			plaintextPacked.Encode(ptm, &pt, 0, chunkSize);
		} catch( std::exception& e ) {
			state.SkipWithError( e.what() );
			break;
		}
	}
}

BENCHMARK_PARMS(BM_encoding_PackedInt)

void BM_Encoding_StringShort(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	IntPlaintextEncoding plaintextInt;
	PackedIntPlaintextEncoding plaintextPacked;
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;
	BigBinaryInteger ptm;
	usint ptmi;
	size_t chunkSize;
	shared_ptr<Ciphertext<ILVector2n>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);

		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = plaintextShort.GetChunksize(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);

		if( ptmi != 2 && ptmi != 4 && ptmi !=16 && ptmi != 256 ) {
			string msg = "Cannot encode with a plaintext modulus of " + std::to_string(ptmi);
			state.SkipWithError(msg.c_str());
		}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		ILVector2n pt(cc.GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		plaintextShort.Encode(ptm, &pt, 0, chunkSize);
	}
}

BENCHMARK_PARMS(BM_Encoding_StringShort)

void BM_Encoding_StringFull(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	IntPlaintextEncoding plaintextInt;
	PackedIntPlaintextEncoding plaintextPacked;
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;
	BigBinaryInteger ptm;
	usint ptmi;
	size_t chunkSize;
	shared_ptr<Ciphertext<ILVector2n>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);

		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = plaintextFull.GetChunksize(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);

		if( ptmi != 2 && ptmi != 4 && ptmi !=16 && ptmi != 256 ) {
			string msg = "Cannot encode with a plaintext modulus of " + std::to_string(ptmi);
			state.SkipWithError(msg.c_str());
		}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		ILVector2n pt(cc.GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		plaintextFull.Encode(ptm, &pt, 0, chunkSize);
	}
}

BENCHMARK_PARMS(BM_Encoding_StringFull)

void BM_Encoding_StringLong(benchmark::State& state) { // benchmark
	CryptoContext<ILVector2n> cc;
	IntPlaintextEncoding plaintextInt;
	PackedIntPlaintextEncoding plaintextPacked;
	BytePlaintextEncoding plaintextShort;
	BytePlaintextEncoding plaintextFull;
	BytePlaintextEncoding plaintextLong;
	BigBinaryInteger ptm;
	usint ptmi;
	size_t chunkSize;
	shared_ptr<Ciphertext<ILVector2n>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper<ILVector2n>::getNewContext(parms[state.range(0)]);

		cc.Enable(ENCRYPTION);
		cc.Enable(SHE);

		ptm = cc.GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = plaintextLong.GetChunksize(cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder(), ptm);

		if( ptmi != 2 && ptmi != 4 && ptmi !=16 && ptmi != 256 ) {
			string msg = "Cannot encode with a plaintext modulus of " + std::to_string(ptmi);
			state.SkipWithError(msg.c_str());
		}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		ILVector2n pt(cc.GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		plaintextLong.Encode(ptm, &pt, 0, chunkSize);
		plaintextLong.Encode(ptm, &pt, chunkSize, chunkSize);
	}
}

BENCHMARK_PARMS(BM_Encoding_StringLong)

//execute the benchmarks
BENCHMARK_MAIN()



