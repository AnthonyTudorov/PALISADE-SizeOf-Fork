/**
 * @file demo-timing.cpp -- Demonstrate the use of the TimingInfo feature of the CryptoContext
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
#include "cryptocontextparametersets.h"
using namespace lbcrypto;
using std::cout;

#include <fstream>
#include <set>
using std::istream;
using std::ostream;
using std::set;

const int MaxIterations = 10;
const int NumInputs = 2;
string progname;

vector<PKESchemeFeature> features( {ENCRYPTION, PRE, SHE, FHE, LEVELEDSHE, MULTIPARTY} );


template<typename Element>
int generateTimings(bool verbose, CryptoContext<Element> cc, usint emask=(ENCRYPTION|PRE|SHE|FHE|LEVELEDSHE|MULTIPARTY)) {

	// enable all the features I was asked to enable
	// remember the ones that were successfully enabled in tmask
	// be silent about failures
	usint tmask = 0;
	for( auto f : features ) {
		try {
			if( emask & f ) {
				cc->Enable(f);
				tmask |= f;
			}
		} catch(...) {}
	}

	// make NumInputs random vectors
	Plaintext inputs[NumInputs];
	{
		auto maxval = cc->GetCryptoParameters()->GetPlaintextModulus() / 2;
		vector<int64_t> vec;
		auto maxentry = cc->GetRingDimension();

		for( size_t i=0; i<NumInputs; i++ ) {
			vec.clear();
			for( size_t n=0; n<maxentry; n++ )
				vec.push_back( (rand() % maxval) * ((rand() % 1) > 0 ? 1 : -1) );
			inputs[i] = cc->MakeCoefPackedPlaintext(vec);
		}
	}

	vector<TimingInfo>	times;
	cc->StartTiming(&times);

	// ENCRYPTION: KeyGen, Encrypt (2 kinds) and Decrypt

	if( verbose )
		cerr << "ENCRYPTION" << endl;

	if( tmask & ENCRYPTION ) {
		for( int nInputs=0; nInputs<NumInputs; nInputs++ ) {
			for( int reps=0; reps < MaxIterations; reps++ ) {
				LPKeyPair<Element> kp = cc->KeyGen();
				auto crypt = cc->Encrypt(kp.publicKey, inputs[nInputs]);
				Plaintext decrypted;
				cc->Decrypt(kp.secretKey, crypt, &decrypted);
				auto crypt2 = cc->Encrypt(kp.secretKey, inputs[nInputs]);
				cc->Decrypt(kp.secretKey, crypt, &decrypted);
			}
		}
	}

	// PKE: ReKeyGen and ReEncrypt

	if( verbose )
		cerr << "PRE" << endl;

	if( tmask & PRE ) {
		bool run1 = true, run2 = true;
		for( int nInputs=0; nInputs<NumInputs; nInputs++ ) {
			for( int reps=0; reps < MaxIterations; reps++ ) {
				LPKeyPair<Element> kp1 = cc->KeyGen();
				LPKeyPair<Element> kp2 = cc->KeyGen();

				auto crypt = cc->Encrypt(kp1.publicKey, inputs[nInputs]);

				if( run1 ) try {
					auto rekey1 = cc->ReKeyGen(kp2.publicKey, kp1.secretKey);
					auto recrypt1 = cc->ReEncrypt(rekey1, crypt);
					Plaintext decrypted1;
					cc->Decrypt(kp2.secretKey, recrypt1, &decrypted1);
				} catch(exception& e) {
					cout << e.what() << endl;
					run1 = false;
				}

				if( run2 ) try {
					auto rekey2 = cc->ReKeyGen(kp2.secretKey, kp1.secretKey);
					auto recrypt2 = cc->ReEncrypt(rekey2, crypt);
					Plaintext decrypted2;
					cc->Decrypt(kp2.secretKey, recrypt2, &decrypted2);
				} catch(exception& e) {
					cout << e.what() << endl;
					run2 = false;
				}
			}
		}
	}

	// SHE: EvalAdd/Sub/Neg/Mult; binary with ciphers and one cipher one pre

	if( verbose )
		cerr << "SHE" << endl;

	if( tmask & SHE ) {
		LPKeyPair<Element> kp = cc->KeyGen();
		cc->EvalMultKeyGen(kp.secretKey);

		auto crypt0 = cc->Encrypt(kp.publicKey, inputs[0]);
		auto crypt1 = cc->Encrypt(kp.publicKey, inputs[1]);

		for (int reps = 0; reps < MaxIterations; reps++) {
			cc->EvalAdd(crypt0, crypt1);
		}

		for (int reps = 0; reps < MaxIterations; reps++) {
			cc->EvalAdd(crypt0, inputs[1]);
		}

		for (int reps = 0; reps < MaxIterations; reps++) {
			cc->EvalSub(crypt0, crypt1);
		}

		for (int reps = 0; reps < MaxIterations; reps++) {
			cc->EvalSub(crypt0, inputs[1]);
		}

		for (int reps = 0; reps < MaxIterations; reps++) {
			cc->EvalMult(crypt0, crypt1);
		}

		for (int reps = 0; reps < MaxIterations; reps++) {
			cc->EvalMult(crypt0, inputs[1]);
		}

		for (int reps = 0; reps < MaxIterations; reps++) {
			cc->EvalNegate(crypt0);
		}

		for (int reps = 0; reps < MaxIterations; reps++) {
			try {
				cc->ModReduce(crypt0);
			} catch( exception& e ) {
				cout << e.what() << endl;
				break;
			}
		}
	}

	// FHE: bootstrap, nothing yet

	// LEVELEDSHE

	// MULTIPARTY


	if( verbose )
		cerr << "Summarizing" << endl;

	// time to assemble timing statistics
	map<OpType,TimingStatistics> stats;

	for( auto& s : times ) {
		cout << s << endl;
	}
	TimingStatistics::GenStatisticsMap(times, stats);

	if( verbose )
		cerr << "Results:" << endl;

	// read them out
	for( auto &tstat : stats ) {
		cout << tstat.first << ':' << tstat.second << endl;
	}

	return 0;
}

void
usage(const string& msg = "") {
	if( msg.length() > 0 ) {
		cerr << msg << endl;
	}
	cerr << "Usage is:" << endl;
	cerr << progname << " [-v] [-dcrt|-poly] [-cfile SERIALIZATION-FILE | -cpre PREDEFINED ]" << endl;
	cerr << "      -poly is the default" << endl;
}

int
main(int argc, char *argv[])
{
	progname = argv[0];

	bool verbose = false;
	enum Element { POLY, DCRT } element = POLY;
	string ctxtFile;
	string ctxtName;

	for( int i=1; i<argc; i++ ) {
		string arg( argv[i] );

		if( arg == "-v" )
			verbose = true;
		else if( arg == "-dcrt" )
			element = DCRT;
		else if( arg == "-poly" )
			element = POLY;
		else if( arg == "-cfile" ) {
			if( i+1 == argc ) {
				usage("Filename missing after -cfile");
				return 1;
			}
			ctxtFile = argv[++i];
		}
		else if( arg == "-cpre" ) {
			if( i+1 == argc ) {
				usage("Context name missing after -cpre");
				return 1;
			}
			ctxtName = argv[++i];
		}
		else {
			usage("Unrecognized argument " + arg);
			return 1;
		}
	}

	CryptoContext<Poly> cc;
	CryptoContext<DCRTPoly> dcc;

	if( ctxtFile.length() == 0 && ctxtName.length() == 0 ) {
		usage("Must specify -cfile or -cpre");
		return 1;
	}

	if( ctxtFile.length() > 0 && ctxtName.length() > 0 ) {
		usage("Must specify -cfile or -cpre, not both!");
		return 1;
	}

	if( ctxtFile.length() > 0 ) {
		ifstream in( ctxtFile );
		if( !in.is_open() ) {
			cout << "Cannot open input file " << ctxtFile << endl;
			return 1;
		}

		Serialized serObj;
		if( SerializableHelper::StreamToSerialization(in, &serObj) == false ) {
			cout << "Input file does not begin with a serialization" << endl;
			return 1;
		}

		if( element == POLY )
			cc = CryptoContextFactory<Poly>::DeserializeAndCreateContext(serObj);
		else
			dcc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(serObj);

	}
	else {
		if( !knownParameterSet(ctxtName) ) {
			cout << ctxtName << " is not a known parameter set name" << endl;
			cout << "Choices are: ";
			CryptoContextHelper::printAllParmSetNames(cout);
			return 1;
		}

		if( element == POLY )
			cc = CryptoContextHelper::getNewContext(ctxtName);
		else
			dcc = CryptoContextHelper::getNewDCRTContext(ctxtName, 3, 20);
	}

	if( cc == 0 && dcc == 0 ) {
		cout << "Unable to create CryptoContext" << endl;
		return 1;
	}

	if( element == POLY )
		return generateTimings(verbose, cc);
	else
		return generateTimings(verbose, dcc);
}
