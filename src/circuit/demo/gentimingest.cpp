/**
 * @file gentimingest.cpp -- Generate timings for timing estimator
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 * reads file of needed timings; generates timings for estimator
 *
 */

#include "palisade.h"
#include "cryptocontextgen.h"
#include "palisadecircuit.h"
using namespace lbcrypto;
using std::cout;

#include <fstream>
#include <set>
using std::istream;
using std::ostream;
using std::set;

const int MaxIterations = 10;
const int NumInputs = 2;

int
main(int argc, char *argv[])
{
	if( argc != 3 ) {
		cout << "Error: usage is" << endl;
		cout << argv[0] << " inputfile outputfile" << endl;
		return 1;
	}

	ifstream in(argv[1]);
	if( !in.is_open() ) {
		cout << "Cannot open input file " << argv[1] << endl;
		return 1;
	}

	ofstream out(argv[2]);
	if( !out.is_open() ) {
		cout << "Cannot open output file " << argv[2] << endl;
		return 1;
	}

	Serialized serObj;
	if( SerializableHelper::StreamToSerialization(in, &serObj) == false ) {
		cout << "Input file does not begin with a serialization" << endl;
		return 1;
	}

	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(serObj);

	if( cc == 0 ) {
		cout << "Unable to deserialize CryptoContext" << endl;
		return 1;
	}

	SerializableHelper::SerializationToStream(serObj, out);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	string operation;
	set<OpType> operations;
	while( in >> operation ) {
		auto fop = OperatorType.find(operation);
		if( fop == OperatorType.end() ) {
			cout << "Unrecognized op " << operation << endl;
			return 1;
		}
		operations.insert(fop->second);
	}
	in.close();

	// set up to encrypt some things
	auto ptm = cc->GetCryptoParameters()->GetPlaintextModulus();
	Plaintext inputs[NumInputs];
	for( size_t i=0; i<NumInputs; i++ ) {
		vector<int64_t> vec;
		vec.clear();
		for( size_t n=0; n<cc->GetRingDimension(); n++ )
			vec.push_back( rand() % ptm );
		inputs[i] = cc->MakeCoefPackedPlaintext(vec);
	}

	vector<TimingInfo>	times;
	cc->StartTiming(&times);
	cc->StopTiming();

	if( operations.count(OpKeyGen) ||
			operations.count(OpEncrypt) ||
			operations.count(OpDecrypt) ) {
		cc->ResumeTiming();
		for( int nInputs=0; nInputs<NumInputs; nInputs++ ) {
			for( int reps=0; reps < MaxIterations; reps++ ) {
				LPKeyPair<DCRTPoly> kp = cc->KeyGen();
				auto crypt = cc->Encrypt(kp.publicKey, inputs[nInputs]);
				Plaintext decrypted;
				cc->Decrypt(kp.secretKey, crypt, &decrypted);
			}
		}
		cc->StopTiming();
	}

#define BINARY_SHE_OP(opfunc,ek) \
		LPKeyPair<DCRTPoly> kp = cc->KeyGen(); \
		auto crypt0 = cc->Encrypt(kp.publicKey, inputs[0]); \
		auto crypt1 = cc->Encrypt(kp.publicKey, inputs[1]); \
		if( ek ) cc->EvalMultKeyGen(kp.secretKey); \
		cc->ResumeTiming(); \
		for (int reps = 0; reps < MaxIterations; reps++) { \
			cc->opfunc(crypt0, crypt1); \
		} \
		cc->StopTiming();

	if( operations.count(OpEvalAdd) ) {
		BINARY_SHE_OP(EvalAdd,false);
	}

	if( operations.count(OpEvalSub) ) {
		BINARY_SHE_OP(EvalSub,false);
	}

	if( operations.count(OpEvalMult) ) {
		BINARY_SHE_OP(EvalMult,true);
	}

#define UNARY_SHE_OP(opfunc) \
		LPKeyPair<DCRTPoly> kp = cc->KeyGen(); \
		auto crypt0 = cc->Encrypt(kp.publicKey, inputs[0]); \
		cc->ResumeTiming(); \
		for (int reps = 0; reps < MaxIterations; reps++) { \
			cc->opfunc(crypt0); \
		} \
		cc->StopTiming();

	if( operations.count(OpEvalNeg) ) {
		UNARY_SHE_OP(EvalNegate);
	}

	if( operations.count(OpModReduce) ) {
		UNARY_SHE_OP(ModReduce);
	}

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
		SerializableHelper::SerializationToStream(ser,out);
	}

	out.close();

	return 0;
}
