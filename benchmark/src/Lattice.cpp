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

using namespace std;
using namespace lbcrypto;

// static table of parms, loaded once
static map<int,shared_ptr<ILParams>> parmsArray;

static shared_ptr<ILParams> getParm(int order) {
	if( parmsArray.find(order) == parmsArray.end() ) {
		BigBinaryInteger modulus("1");
		NextQ(modulus, BigBinaryInteger("2"), order, BigBinaryInteger("4"), BigBinaryInteger("4"));

		parmsArray[order] = shared_ptr<ILParams>(new ILParams(order, modulus));
	}

	return parmsArray[order];
}

static void CustomParmSizes(benchmark::internal::Benchmark *b) {
	for( int o=8; o<=4096; o*=2 ) {
		getParm(o);
		b->Arg(o);
	}
}

static void make_LATTICE_empty(shared_ptr<ILParams>& params) {
	ILVector2n v1(params);
	ILVector2n v2(params);
}

void BM_LATTICE_empty(benchmark::State& state) { // benchmark
	shared_ptr<ILParams> params;
	if( state.thread_index == 0 ) {
		params = getParm(state.range(0));
	}

	while (state.KeepRunning()) {
		make_LATTICE_empty(params);
	}
}


BENCHMARK(BM_LATTICE_empty)->Apply(CustomParmSizes);

static ILVector2n makeVector(shared_ptr<ILParams>& params) {
	ILVector2n			elem(params);
	int vecsize = params->GetCyclotomicOrder()/2;

	BigBinaryVector		vec(vecsize, params->GetModulus());
	for( int i=0; i<vecsize; i++ )
		vec.SetValAtIndex(i, BigBinaryInteger(i));

	elem.SetValues(vec, elem.GetFormat());

	return std::move(elem);
}

// make variables

static void make_LATTICE_vector (shared_ptr<ILParams>& params) {	// function
	ILVector2n			elem = makeVector(params);
}


void BM_LATTICE_vector(benchmark::State& state) { // benchmark
	shared_ptr<ILParams> params;
	if( state.thread_index == 0 ) {
		params = getParm(state.range(0));
	}

	while (state.KeepRunning()) {
		make_LATTICE_vector(params);		// note even with -O3 it appears
		// this is not optimized out
		// though check with your compiler
	}
}

BENCHMARK(BM_LATTICE_vector)->Apply(CustomParmSizes);		// register benchmark

// add
static void add_LATTICE(shared_ptr<ILParams>& params) {	// function
	ILVector2n			a = makeVector(params);
	ILVector2n			b = makeVector(params);

	ILVector2n c1 = a+b;
}

static void BM_add_LATTICE(benchmark::State& state) { // benchmark
	shared_ptr<ILParams> params;
	if( state.thread_index == 0 ) {
		params = getParm(state.range(0));
	}

	while (state.KeepRunning()) {
		add_LATTICE(params);
	}
}

BENCHMARK(BM_add_LATTICE)->Apply(CustomParmSizes);;		// register benchmark

// add
static void mult_LATTICE(shared_ptr<ILParams>& params) {	// function
	ILVector2n			a = makeVector(params);
	ILVector2n			b = makeVector(params);

	ILVector2n c1 = a*b;
}

static void BM_mult_LATTICE(benchmark::State& state) { // benchmark
	shared_ptr<ILParams> params;
	if( state.thread_index == 0 ) {
		params = getParm(state.range(0));
	}

	while (state.KeepRunning()) {
		mult_LATTICE(params);
	}
}

BENCHMARK(BM_mult_LATTICE)->Apply(CustomParmSizes);;		// register benchmark

static void switchformat_LATTICE(shared_ptr<ILParams>& params) {
	ILVector2n  v = makeVector(params);

	v.SwitchFormat();
}

static void BM_switchformat_LATTICE(benchmark::State& state) { // benchmark
	shared_ptr<ILParams> params;
	if( state.thread_index == 0 ) {
		params = getParm(state.range(0));
	}

	while (state.KeepRunning()) {
		switchformat_LATTICE(params);
	}
}

BENCHMARK(BM_switchformat_LATTICE)->Apply(CustomParmSizes);

//execute the benchmarks
BENCHMARK_MAIN()
