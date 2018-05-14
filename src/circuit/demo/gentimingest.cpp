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

void usage(string msg) {
	cout << "usage is" << endl;
	cout << msg << " [-poly|-dcrt] context-serialization outputfile" << endl;
	cout << "   -poly is default" << endl;

}

int
main(int argc, char *argv[])
{
	enum Element { POLY, DCRT } element = POLY;

	if( argc != 3 && argc != 4 ) {
		usage(argv[0]);
		return 1;
	}

	int aidx = 1;
	if( argc == 4 ) {
		aidx = 2;
		string arg( argv[1] );

		if( arg == "-dcrt" )
			element = DCRT;
		else if( arg == "-poly" )
			element = POLY;
		else {
			usage(argv[0]);
			return 1;
		}
	}

	Serialized serObj;
	if( SerializableHelper::ReadSerializationFromFile(argv[aidx], &serObj) == false ) {
		cout << "Unable to read CryptoContext" << endl;
		return 1;
	}

	CryptoContext<Poly> cc;
	CryptoContext<DCRTPoly> dcc;

	if( element == POLY ) {
		cc = CryptoContextFactory<Poly>::DeserializeAndCreateContext(serObj);
	}
	else {
		dcc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(serObj);
	}

	if( cc == 0 && dcc == 0 ) {
		cout << "Unable to deserialize CryptoContext" << endl;
		return 1;
	}

	++aidx;

	ofstream out(argv[aidx]);
	if( !out.is_open() ) {
		cout << "Cannot open output file " << argv[aidx] << endl;
		return 1;
	}

	// save the context with the data
	SerializableHelper::SerializationToStream(serObj, out);

	TimingStatisticsMap stats;
	PlaintextEncodings pte = Packed;
	if( element == POLY ) {
		generateTimings(stats, cc, pte);
	}
	else {
		generateTimings(stats, dcc, pte);
	}

	// read them out
	for( auto &tstat : stats ) {
		auto ts = tstat.second;

		cout << ts << endl;
		Serialized mSer;
		ts.Serialize(&mSer);
		SerializableHelper::SerializationToStream(mSer, out);
	}

	out.close();

	return 0;
}
