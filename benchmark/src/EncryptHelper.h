/*
 * EncryptHelper.h
 *
 *  Created on: Feb 25, 2017
 *      Author: gerardryan
 */

#ifndef BENCHMARK_SRC_ENCRYPTHELPER_H_
#define BENCHMARK_SRC_ENCRYPTHELPER_H_

#include "cryptocontexthelper.h"
#include "cryptocontextparametersets.h"
#include <string>
#include <map>
#include <vector>
using namespace std;

// include this file in benchmarks testing PKE operations across various predefined schemes

static vector<string> parms;

class MakeParms {
public:
	MakeParms() {
		for( auto p : lbcrypto::CryptoContextParameterSets )
			parms.push_back(p.first);

		if( parms.size() != 20 )
			cout << "WARNING: fix macros in EncryptHelper.h, size should be " << parms.size() << endl;
	}
};

static MakeParms makeParms;

#define BENCHMARK_PARMS(X) \
BENCHMARK(X)->ArgName(parms[0])->Arg(0); \
BENCHMARK(X)->ArgName(parms[1])->Arg(1); \
BENCHMARK(X)->ArgName(parms[2])->Arg(2); \
BENCHMARK(X)->ArgName(parms[3])->Arg(3); \
BENCHMARK(X)->ArgName(parms[4])->Arg(4); \
BENCHMARK(X)->ArgName(parms[5])->Arg(5); \
BENCHMARK(X)->ArgName(parms[6])->Arg(6); \
BENCHMARK(X)->ArgName(parms[7])->Arg(7); \
BENCHMARK(X)->ArgName(parms[8])->Arg(8); \
BENCHMARK(X)->ArgName(parms[9])->Arg(9); \
BENCHMARK(X)->ArgName(parms[10])->Arg(10); \
BENCHMARK(X)->ArgName(parms[11])->Arg(11); \
BENCHMARK(X)->ArgName(parms[12])->Arg(12); \
BENCHMARK(X)->ArgName(parms[13])->Arg(13); \
BENCHMARK(X)->ArgName(parms[14])->Arg(14); \
BENCHMARK(X)->ArgName(parms[15])->Arg(15); \
BENCHMARK(X)->ArgName(parms[16])->Arg(16); \
BENCHMARK(X)->ArgName(parms[17])->Arg(17); \
BENCHMARK(X)->ArgName(parms[18])->Arg(18); \
BENCHMARK(X)->ArgName(parms[19])->Arg(19);

#define BENCHMARK_PARMS_TEMPLATE(X,Y) \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[0])->Arg(0); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[1])->Arg(1); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[2])->Arg(2); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[3])->Arg(3); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[4])->Arg(4); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[5])->Arg(5); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[6])->Arg(6); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[7])->Arg(7); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[8])->Arg(8); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[9])->Arg(9); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[10])->Arg(10); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[11])->Arg(11); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[12])->Arg(12); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[13])->Arg(13); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[14])->Arg(14); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[15])->Arg(15); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[16])->Arg(16); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[17])->Arg(17); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[18])->Arg(18); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[19])->Arg(19);


#endif /* BENCHMARK_SRC_ENCRYPTHELPER_H_ */
