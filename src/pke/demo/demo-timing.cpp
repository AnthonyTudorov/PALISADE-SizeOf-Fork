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

int MaxIterations = 100;
unsigned int NumInputs = 10;
bool PrintSizes = false;
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

	cout << *cc->GetCryptoParameters() << endl;

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

	// note we can NOT use the TimingInfo on a Windows platform because
	// of clock granularity (or lack thereof)
	// Therefore we simply repeat the calls and calculate an average
	//	vector<TimingInfo>	times;
	//	cc->StartTiming(&times);

	// container for timing statistics
	map<OpType,TimingStatistics*> stats;
	TimeVar t;
	double span;

	// ENCRYPTION: KeyGen, Encrypt (2 kinds) and Decrypt

	if( verbose )
		cerr << "ENCRYPTION" << endl;

	LPKeyPair<Element> kp;
	Ciphertext<Element> crypt;

	if( tmask & ENCRYPTION ) {
		TIC(t);
		for( int reps=0; reps < MaxIterations; reps++ ) {
			kp = cc->KeyGen();
		}
		span = TOC_MS(t);
		stats[OpKeyGen] = new TimingStatistics(OpKeyGen, MaxIterations, span);

		Plaintext decrypted;

		crypt = cc->Encrypt(kp.publicKey, inputs[0]);
		TIC(t);
		for( int reps=0; reps < MaxIterations; reps++ ) {
			crypt = cc->Encrypt(kp.publicKey, inputs[0]);
		}
		span = TOC_MS(t);
		stats[OpEncryptPub] = new TimingStatistics(OpType::OpEncryptPub, MaxIterations, span);

		if( PrintSizes ) {

		}

		auto crypt2 = cc->Encrypt(kp.publicKey, inputs[0]);
		TIC(t);
		for( int reps=0; reps < MaxIterations; reps++ ) {
			crypt2 = cc->Encrypt(kp.secretKey, inputs[0]);
		}
		span = TOC_MS(t);
		stats[OpEncryptPriv] = new TimingStatistics(OpType::OpEncryptPriv, MaxIterations, span);

		TIC(t);
		for( int reps=0; reps < MaxIterations; reps++ ) {
			cc->Decrypt(kp.secretKey, crypt, &decrypted);
		}
		span = TOC_MS(t);
		stats[OpDecrypt] = new TimingStatistics(OpType::OpDecrypt, MaxIterations, span);
	}

	// PKE: ReKeyGen and ReEncrypt

	if( verbose )
		cerr << "PRE" << endl;

	Ciphertext<Element> recrypt;
	LPEvalKey<Element> rekey1, rekey2;

	if( tmask & PRE ) {
		bool runPubPri = true, runPriPri = true;
		LPKeyPair<Element> kp1 = cc->KeyGen();
		LPKeyPair<Element> kp2 = cc->KeyGen();

		crypt = cc->Encrypt(kp1.publicKey, inputs[0]);

		Plaintext decrypted;

		try {
			rekey1 = cc->ReKeyGen(kp2.publicKey, kp1.secretKey);
			recrypt = cc->ReEncrypt(rekey1, crypt);
		} catch(exception& e) {
			cout << e.what() << endl;
			runPubPri = false;
		}

		try {
			rekey2 = cc->ReKeyGen(kp2.secretKey, kp1.secretKey);
			recrypt = cc->ReEncrypt(rekey2, crypt);
		} catch(exception& e) {
			cout << e.what() << endl;
			runPriPri = false;
		}

		if( runPubPri ) {
			TIC(t);
			for( int reps=0; reps < MaxIterations; reps++ ) {
				rekey1 = cc->ReKeyGen(kp2.publicKey, kp1.secretKey);
			}
			span = TOC_MS(t);
			stats[OpReKeyGenPubPri] = new TimingStatistics(OpType::OpReKeyGenPubPri, MaxIterations, span);

			TIC(t);
			for( int reps=0; reps < MaxIterations; reps++ ) {
				recrypt = cc->ReEncrypt(rekey1, crypt);
			}
			span = TOC_MS(t);
			stats[OpReEncrypt] = new TimingStatistics(OpType::OpReEncrypt, MaxIterations, span);

			TIC(t);
			for( int reps=0; reps < MaxIterations; reps++ ) {
				cc->Decrypt(kp2.secretKey, recrypt, &decrypted);
			}
			span = TOC_MS(t);
			stats[OpDecrypt] = new TimingStatistics(OpType::OpDecrypt, MaxIterations, span);
		}

		if( runPriPri ) {
			TIC(t);
			for( int reps=0; reps < MaxIterations; reps++ ) {
				rekey2 = cc->ReKeyGen(kp2.secretKey, kp1.secretKey);
			}
			span = TOC_MS(t);
			stats[OpReKeyGenPriPri] = new TimingStatistics(OpType::OpReKeyGenPriPri, MaxIterations, span);

			TIC(t);
			for( int reps=0; reps < MaxIterations; reps++ ) {
				recrypt = cc->ReEncrypt(rekey2, crypt);
			}
			span = TOC_MS(t);
			stats[OpReEncrypt] = new TimingStatistics(OpType::OpReEncrypt, MaxIterations, span);

			TIC(t);
			for( int reps=0; reps < MaxIterations; reps++ ) {
				cc->Decrypt(kp2.secretKey, recrypt, &decrypted);
			}
			span = TOC_MS(t);
			stats[OpDecrypt] = new TimingStatistics(OpType::OpDecrypt, MaxIterations, span);
		}
	}

	// SHE: EvalAdd/Sub/Neg/Mult; binary with ciphers and one cipher one pre

	if( verbose )
		cerr << "SHE" << endl;

	if( tmask & SHE ) {
		LPKeyPair<Element> kp = cc->KeyGen();
		try {
			cc->EvalMultKeyGen(kp.secretKey);

			auto crypt0 = cc->Encrypt(kp.publicKey, inputs[0]);
			auto crypt1 = cc->Encrypt(kp.publicKey, inputs[1]);

			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				cc->EvalAdd(crypt0, crypt1);
			}
			span = TOC_MS(t);
			stats[OpEvalAdd] = new TimingStatistics(OpType::OpEvalAdd, MaxIterations, span);

			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				cc->EvalAdd(crypt0, inputs[1]);
			}
			span = TOC_MS(t);
			stats[OpEvalAddPlain] = new TimingStatistics(OpType::OpEvalAddPlain, MaxIterations, span);

			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				cc->EvalSub(crypt0, crypt1);
			}
			span = TOC_MS(t);
			stats[OpEvalSub] = new TimingStatistics(OpType::OpEvalSub, MaxIterations, span);

			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				cc->EvalSub(crypt0, inputs[1]);
			}
			span = TOC_MS(t);
			stats[OpEvalSubPlain] = new TimingStatistics(OpType::OpEvalSubPlain, MaxIterations, span);

			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				cc->EvalMult(crypt0, crypt1);
			}
			span = TOC_MS(t);
			stats[OpEvalMult] = new TimingStatistics(OpType::OpEvalMult, MaxIterations, span);

			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				cc->EvalMult(crypt0, inputs[1]);
			}
			span = TOC_MS(t);
			stats[OpEvalMultPlain] = new TimingStatistics(OpType::OpEvalMultPlain, MaxIterations, span);

			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				cc->EvalNegate(crypt0);
			}
			span = TOC_MS(t);
			stats[OpEvalNeg] = new TimingStatistics(OpType::OpEvalNeg, MaxIterations, span);

			bool hasMR = true;
			TIC(t);
			for (int reps = 0; reps < MaxIterations; reps++) {
				try {
					cc->ModReduce(crypt0);
				} catch( exception& e ) {
					cout << e.what() << endl;
					hasMR = false;
					break;
				}
			}
			if( hasMR ) {
				span = TOC_MS(t);
				stats[OpModReduce] = new TimingStatistics(OpType::OpModReduce, MaxIterations, span);
			}
		} catch(exception& e) {
			cout << e.what() << endl;
		}
	}

	// FHE: bootstrap, nothing yet

	// LEVELEDSHE

	// MULTIPARTY

	if( verbose )
		cerr << "Results:" << endl;

	// read them out
	for( auto &tstat : stats ) {
		cout << tstat.second->operation << ": " << tstat.second->average << "ms" <<endl;
	}

	Serialized ser;
	string str;

#define PSSIZE(msg,x) { \
		Serialized ser; string str; \
		if( (x)->Serialize(&ser) ) {\
			SerializableHelper::SerializationToString(ser, str); \
			cout << (msg) << str.length() << endl; \
		} \
}

	if( PrintSizes ) {
		cout << endl;
		cout << "Plaintext: array of " << cc->GetRingDimension() << " "
				<< (sizeof(int64_t) * 8) << " bit integers: "
				<< cc->GetRingDimension()*sizeof(int64_t) << endl;

		//cout << "Plaintext size: " << sizeof( *inputs[0] ) << endl;
		PSSIZE("Public key size: ", kp.publicKey );
		PSSIZE("Private key size: ", kp.secretKey );
		PSSIZE("Ciphertext size : ", crypt );
		if( rekey1 ) PSSIZE("PRE Key 1 size: ", rekey1 );
		if( rekey2 ) PSSIZE("PRE Key 2 size: ", rekey2 );
	}


	return 0;
}

void
usage(const string& msg = "") {
	if( msg.length() > 0 ) {
		cerr << msg << endl;
	}
	cerr << "Usage is:" << endl;
	cerr << progname <<
			" [-v] [-i iteration_count] [-printsizes] [-dcrt|-poly|-native] [-cfile SERIALIZATION-FILE | -cpre PREDEFINED ]"
			<< endl;
	cerr << "      -poly is the default" << endl;
}

int
main(int argc, char *argv[])
{
	progname = argv[0];

	bool verbose = false;
	enum Element { POLY, DCRT, NATIVE } element = POLY;
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
		else if( arg == "-native" )
			element = NATIVE;
		else if( arg == "-printsizes" )
			PrintSizes = true;
		else if( arg == "-i" ) {
			if( i+1 == argc ) {
				usage("Filename missing after -cfile");
				return 1;
			}
			MaxIterations = stoi(argv[++i]);
		}
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
	CryptoContext<NativePoly> ncc;

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
		else if( element == DCRT )
			dcc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(serObj);
		else
			ncc = CryptoContextFactory<NativePoly>::DeserializeAndCreateContext(serObj);

	}
	else {
		if( !knownParameterSet(ctxtName) ) {
			cout << ctxtName << " is not a known parameter set name" << endl;
			cout << "Choices are: ";
			CryptoContextHelper::printAllParmSetNames(cout);
			return 1;
		}

		cout << "Crypto context: " << ctxtName << endl;

		if( element == POLY )
			cc = CryptoContextHelper::getNewContext(ctxtName);
		else if( element == DCRT )
			dcc = CryptoContextHelper::getNewDCRTContext(ctxtName, 3, 20);
		else {

		}
	}

	if( cc == 0 && dcc == 0 && ncc == 0 ) {
		cout << "Unable to create CryptoContext" << endl;
		return 1;
	}

	if( element == POLY )
		return generateTimings(verbose, cc);
	else if( element == DCRT )
		return generateTimings(verbose, dcc);
	else
		return generateTimings(verbose, ncc);
}
