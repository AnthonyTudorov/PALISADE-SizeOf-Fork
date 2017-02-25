/*
 * EncryptHelper.h
 *
 *  Created on: Feb 25, 2017
 *      Author: gerardryan
 */

#ifndef BENCHMARK_SRC_ENCRYPTHELPER_H_
#define BENCHMARK_SRC_ENCRYPTHELPER_H_

#include <string>
using namespace std;

// include this file in benchmarks testing PKE operations across various predefined schemes

string parms[] = { "Null", "Null2", "LTV5", "FV1", "FV2" };

#define BENCHMARK_PARMS(X) \
BENCHMARK(X)->ArgName(parms[0])->Arg(0); \
BENCHMARK(X)->ArgName(parms[1])->Arg(1); \
BENCHMARK(X)->ArgName(parms[2])->Arg(2); \
BENCHMARK(X)->ArgName(parms[3])->Arg(3); \
BENCHMARK(X)->ArgName(parms[4])->Arg(4);

#define BENCHMARK_PARMS_TEMPLATE(X,Y) \
BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[0])->Arg(0); \
BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[1])->Arg(1); \
BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[2])->Arg(2); \
BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[3])->Arg(3); \
BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[4])->Arg(4);


#endif /* BENCHMARK_SRC_ENCRYPTHELPER_H_ */
