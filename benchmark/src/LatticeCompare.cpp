/*
 * LatticeCompare.cpp
 *
 *  Created on: Mar 9, 2017
 *      Author: gerardryan
 */

/*
  PALISADE PROJECT, Crypto Lab, NJIT
  Version:
  v00.01
  Last Edited:

  List of Authors:
  TPOC:
  Dr. Kurt Rohloff, rohloff@njit.edu
  Programmers:
  Gerard Ryan (gwryan@njit.edu)

  Description:
  This code benchmarks functions of the src/lib/lattoce directory  of the PALISADE lattice encryption library.

  License Information:

  Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
  All rights reserved.
  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "benchmark/benchmark_api.h"

#include <iostream>
#define _USE_MATH_DEFINES
#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "utils/utilities.h"

#include <vector>

#include "BBVhelper.h"
#include "ElementParmsHelper.h"

using namespace std;
using namespace lbcrypto;

typedef native64::BigBinaryInteger  nativeInt;

typedef cpu_int::BigBinaryInteger<uint32_t,64>  smallInt32_64;

typedef cpu_int::BigBinaryInteger<uint32_t,128>  smallInt32_128;

typedef cpu_int::BigBinaryInteger<uint64_t,64>  smallInt64_64;

typedef cpu_int::BigBinaryInteger<uint64_t,128>  smallInt64_128;

map<int,map<int,string>> primes;
map<int,map<int,string>> roots;

bool ranloadprimes = false;
void
loadprimes()
{
	if( ranloadprimes ) return;
	ranloadprimes = true;
	for( int n = 1024; n <=8192; n *= 2 ) {
		for( int mbits = 30; mbits <= 60; mbits *= 2 ) {
			primes[mbits][n] = FindPrimeModulus<nativeInt>(n, mbits).ToString();
			roots[mbits][n] = RootOfUnity<nativeInt>(n, primes[mbits][n]).ToString();
		}
	}
}

static void CustomArguments(benchmark::internal::Benchmark* b) {
	for( int n = 1024; n <=8192; n *= 2 ) {
		for( int mbits = 30; mbits <= 60; mbits *= 2 ) {
			b->Args({n, mbits});
		}
	}
}

template <typename IntType>
static ILVectorImpl<IntType,cpu_int::BigBinaryVector<IntType>,ILParamsImpl<IntType>> makeElement(benchmark::State& state) {
	int n = state.range(0);
	int w = state.range(1);
	shared_ptr<ILParamsImpl<IntType>> params( new ILParamsImpl<IntType>(n, IntType(primes[n][w]), IntType(roots[n][w])) );
	cpu_int::BigBinaryVector<IntType> vec(params->GetCyclotomicOrder()/2, params->GetModulus());
	ILVectorImpl<IntType,cpu_int::BigBinaryVector<IntType>,ILParamsImpl<IntType>>	elem(params);
	elem.SetValues(vec, elem.GetFormat());
	return std::move(elem);
}

// add
template <typename IntType>
static void add_LATTICE(benchmark::State& state) {
	state.PauseTiming();
	loadprimes();
	ILVectorImpl<IntType,cpu_int::BigBinaryVector<IntType>,ILParamsImpl<IntType>>			a = makeElement<IntType>(state);
	ILVectorImpl<IntType,cpu_int::BigBinaryVector<IntType>,ILParamsImpl<IntType>>			b = makeElement<IntType>(state);
	state.ResumeTiming();

	ILVectorImpl<IntType,cpu_int::BigBinaryVector<IntType>,ILParamsImpl<IntType>> c1 = a+b;
}

template <class E>
static void BM_add_LATTICE(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
		add_LATTICE<E>(state);
	}
}

BENCHMARK_TEMPLATE(BM_add_LATTICE,nativeInt)->Apply(CustomArguments);

#ifdef OUT
template <class E>
static void mult_LATTICE(benchmark::State& state, shared_ptr<ILParams>& params) {	// function
	state.PauseTiming();
	E			a = makeElement<E>(state, params);
	E			b = makeElement<E>(state, params);
	state.ResumeTiming();

	E c1 = a*b;
}

template <class E>
static void BM_mult_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		mult_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_mult_LATTICE,ILVector2n)

template <class E>
static void switchformat_LATTICE(benchmark::State& state, shared_ptr<ILParams>& params) {
	state.PauseTiming();
	E			a = makeElement<E>(state, params);
	state.ResumeTiming();

	a.SwitchFormat();
}

template <class E>
static void BM_switchformat_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		switchformat_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,ILVector2n)
#endif

//execute the benchmarks
BENCHMARK_MAIN()



