/*
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

#define _USE_MATH_DEFINES
#include "benchmark/benchmark_api.h"

bool runOnlyOnce = true;

#include <iostream>
#include <fstream>
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "EncryptHelper.h"

using namespace std;
using namespace lbcrypto;

static void initializeBytes(int ring, const BigInteger& ptm,
		string& plaintextShort,
		string& plaintextFull,
		string& plaintextLong) {

	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};

	string shortStr(ring/2,0);
	std::generate_n(shortStr.begin(), ring/2, randchar);
	plaintextShort = shortStr;

	string fullStr(ring,0);
	std::generate_n(fullStr.begin(), ring, randchar);
	plaintextFull = fullStr;

	string longStr(ring*2,0);
	std::generate_n(longStr.begin(), ring*2, randchar);
	plaintextLong = longStr;
}


static void setup_Encoding(shared_ptr<CryptoContext<Poly>> cc,
		shared_ptr<Plaintext>& plaintextInt,
		shared_ptr<Plaintext>& plaintextPacked,
		shared_ptr<Plaintext>& plaintextShort,
		shared_ptr<Plaintext>& plaintextFull,
		shared_ptr<Plaintext>& plaintextLong) {

	int nel = cc->GetRingDimension();
	const BigInteger& ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
	uint32_t ptmi = ptm.ConvertToInt();

	vector<uint32_t> intvec;
	for( int ii=0; ii<nel; ii++)
		intvec.push_back( rand() % ptmi );

	plaintextInt = cc->MakeCoefPackedPlaintext(intvec);
	plaintextPacked = cc->MakePackedPlaintext(intvec);

	string ss, fs, ls;
	initializeBytes(nel, ptm, ss, fs, ls);

	plaintextShort = cc->MakeStringPlaintext(ss);
	plaintextFull = cc->MakeStringPlaintext(fs);
	plaintextLong = cc->MakeStringPlaintext(ls);
}

void BM_encoding_Int(benchmark::State& state) { // benchmark
	shared_ptr<CryptoContext<Poly>> cc;
	shared_ptr<Plaintext> plaintextInt;
	shared_ptr<Plaintext> plaintextPacked;
	shared_ptr<Plaintext> plaintextShort;
	shared_ptr<Plaintext> plaintextFull;
	shared_ptr<Plaintext> plaintextLong;
	BigInteger ptm;
	usint ptmi;
	size_t chunkSize = 0;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = cc->GetRingDimension();
		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		Poly pt(cc->GetElementParams());
		state.ResumeTiming();

		plaintextInt->Encode();
	}
}

BENCHMARK_PARMS(BM_encoding_Int)

void BM_encoding_PackedInt(benchmark::State& state) { // benchmark
	shared_ptr<CryptoContext<Poly>> cc;
	shared_ptr<Plaintext> plaintextInt;
	shared_ptr<Plaintext> plaintextPacked;
	shared_ptr<Plaintext> plaintextShort;
	shared_ptr<Plaintext> plaintextFull;
	shared_ptr<Plaintext> plaintextLong;
	BigInteger ptm;
	usint ptmi;
	size_t chunkSize = 0;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		try {
			cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
			cc->Enable(ENCRYPTION);
			cc->Enable(SHE);

			ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
			ptmi = ptm.ConvertToInt();

			setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
			chunkSize = plaintextPacked.GetChunksize(cc->GetCryptoParameters()->GetElementParams()->GetRingDimension(), ptm);
		} catch( const std::exception& e ) {
			state.SkipWithError( e.what() );
		}
		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		Poly pt(cc->GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		try {
			plaintextPacked->Encode();
		} catch( std::exception& e ) {
			state.SkipWithError( e.what() );
			break;
		}
	}
}

BENCHMARK_PARMS(BM_encoding_PackedInt)

void BM_Encoding_StringShort(benchmark::State& state) { // benchmark
	shared_ptr<CryptoContext<Poly>> cc;
	shared_ptr<Plaintext> plaintextInt;
	shared_ptr<Plaintext> plaintextPacked;
	shared_ptr<Plaintext> plaintextShort;
	shared_ptr<Plaintext> plaintextFull;
	shared_ptr<Plaintext> plaintextLong;
	BigInteger ptm;
	usint ptmi;
	size_t chunkSize = 0;
	shared_ptr<Ciphertext<Poly>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = cc->GetRingDimension();

		if( ptmi != 256 ) {
			string msg = "Cannot encode with a plaintext modulus of " + std::to_string(ptmi);
			state.SkipWithError(msg.c_str());
		}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		Poly pt(cc->GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		plaintextShort->Encode();
	}
}

BENCHMARK_PARMS(BM_Encoding_StringShort)

void BM_Encoding_StringFull(benchmark::State& state) { // benchmark
	shared_ptr<CryptoContext<Poly>> cc;
	shared_ptr<Plaintext> plaintextInt;
	shared_ptr<Plaintext> plaintextPacked;
	shared_ptr<Plaintext> plaintextShort;
	shared_ptr<Plaintext> plaintextFull;
	shared_ptr<Plaintext> plaintextLong;
	BigInteger ptm;
	usint ptmi;
	size_t chunkSize = 0;
	shared_ptr<Ciphertext<Poly>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = cc->GetRingDimension();

		if( ptmi != 256 ) {
			string msg = "Cannot encode with a plaintext modulus of " + std::to_string(ptmi);
			state.SkipWithError(msg.c_str());
		}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		Poly pt(cc->GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		plaintextFull->Encode();
	}
}

BENCHMARK_PARMS(BM_Encoding_StringFull)

void BM_Encoding_StringLong(benchmark::State& state) { // benchmark
	shared_ptr<CryptoContext<Poly>> cc;
	shared_ptr<Plaintext> plaintextInt;
	shared_ptr<Plaintext> plaintextPacked;
	shared_ptr<Plaintext> plaintextShort;
	shared_ptr<Plaintext> plaintextFull;
	shared_ptr<Plaintext> plaintextLong;
	BigInteger ptm;
	usint ptmi;
	size_t chunkSize = 0;
	shared_ptr<Ciphertext<Poly>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);

		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
		ptmi = ptm.ConvertToInt();

		setup_Encoding(cc, plaintextInt, plaintextPacked, plaintextShort, plaintextFull, plaintextLong);
		chunkSize = cc->GetRingDimension();

		if( ptmi != 256 ) {
			string msg = "Cannot encode with a plaintext modulus of " + std::to_string(ptmi);
			state.SkipWithError(msg.c_str());
		}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		Poly pt(cc->GetCryptoParameters()->GetElementParams());
		state.ResumeTiming();

		plaintextLong->Encode();
	}
}

BENCHMARK_PARMS(BM_Encoding_StringLong)

//execute the benchmarks
BENCHMARK_MAIN()



