/*
 * SHE.cpp
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


#include <iostream>
#include <fstream>
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "EncryptHelper.h"

using namespace std;
using namespace lbcrypto;

static std::vector<uint32_t> makeVector(int siz, int ptmi) {
	std::vector<uint32_t>			elem;

	for( int i=0; i<siz; i++ )
		elem.push_back(i%ptmi);

	return elem;
}

static bool setup_SHE(CryptoContext<Poly> cc, shared_ptr<Ciphertext<Poly>>& ct1, shared_ptr<Ciphertext<Poly>>& ct2) {
	int nel = cc->GetCyclotomicOrder()/2;
	const BigInteger& ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
	uint32_t ptmi = ptm.ConvertToInt();

	LPKeyPair<Poly> kp = cc->KeyGen();

	Plaintext p1 = cc->MakeCoefPackedPlaintext( makeVector(nel, ptmi) );
	Plaintext p2 = cc->MakeCoefPackedPlaintext( makeVector(nel, ptmi) );

	ct1 = cc->Encrypt(kp.publicKey, p1);
	ct2 = cc->Encrypt(kp.publicKey, p2);

	try {
		cc->EvalMultKeyGen(kp.secretKey);
	} catch(...) {
		return false;
	}

	return true;
}

void BM_evalAdd_SHE(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	shared_ptr<Ciphertext<Poly>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		setup_SHE(cc, ct1, ct2);
		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		shared_ptr<Ciphertext<Poly>> ctP = cc->EvalAdd(ct1, ct2);
	}
}

BENCHMARK_PARMS(BM_evalAdd_SHE)

void BM_evalMult_SHE(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	shared_ptr<Ciphertext<Poly>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(SHE);

		bool isSetup = setup_SHE(cc, ct1, ct2);
		state.ResumeTiming();
		if( !isSetup )
			state.SkipWithError("Setup failed: EvalMultKeyGen not supported?");
	}

	while (state.KeepRunning()) {
		shared_ptr<Ciphertext<Poly>> ctP = cc->EvalMult(ct1, ct2);
	}
}

BENCHMARK_PARMS(BM_evalMult_SHE)

void BM_baseDecompose_SHE(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	shared_ptr<Ciphertext<Poly>> ct1, ct2;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		try {
			cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
			cc->Enable(ENCRYPTION);
			cc->Enable(SHE);

			setup_SHE(cc, ct1, ct2);
		} catch( std::exception& e ) {
			state.SkipWithError( "Unable to set up for BaseDecompose" );
		}
		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		try {
			vector<Poly> ctP = ct1->GetElements()[0].BaseDecompose(2);
		} catch( std::exception& e ) {
			state.SkipWithError( e.what() );
			break;
		}
	}
}

BENCHMARK_PARMS(BM_baseDecompose_SHE)

//execute the benchmarks
BENCHMARK_MAIN()

