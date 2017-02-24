/*
  PALISADE PROJECT, Crypto Lab, NJIT
  Version: 
  v00.01 
  Last Edited: 

  List of Authors:
  TPOC: 
  Dr. Kurt Rohloff, rohloff@njit.edu
  Programmers:
  Dr. Yuriy Polyakov, polyakov@njit.edu
  Gyana Sahu, grs22@njit.edu
  Nishanth Pasham, np386@njit.edu
  Dr. David Bruce Cousins dcousins@bbn.com [benchmark]
  Description:	
  This code benchmarks functions of the math directory  of the PALISADE lattice encryption library.

  License Information:

  Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
  All rights reserved.
  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "benchmark/benchmark_api.h"


/* this is an example of very basic google benchmarks
   all the benchmarks have
             no input parameters
	     cannot runover differnt length operations
	     some generate an output
  future examples will show the use of fixtures and templates to reduce
  the amount of 
  code needed

  for documentation on google benchmarks see https://github.com/google/benchmark
  as well as example code in the benchmark/examples directory

  note to increase the number of iterations call it as follows
             ./BBVMath --benchmark_min_time=4.0


  increase the min_time (as a float) to increase the # iterations

 */


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

#include "BBVhelper.h"

using namespace std;
using namespace lbcrypto;

//four simple benchmarks to test constructing BBVs
// typically the code to benchmark is in a 'function' that is then
// called within the actual benchmark.

static BigBinaryInteger mod("31415");

// test BBV constants
static void make_BBV_constants(int siz) {	// function
	BigBinaryVector one(siz, mod);
}

void BM_BBV_constants(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
		make_BBV_constants(state.range(0));		// note even with -O3 it appears
		// this is not optimized out
		// though check with your compiler
	}
}

BENCHMARK(BM_BBV_constants)->Arg(256)->Arg(512)->Arg(1024)->Arg(2048)->Arg(4096);		// register benchmark

// add
static void add_BBV(benchmark::State& state) {
	state.PauseTiming();
	BigBinaryVector a = makeVector(state.range(0), mod), b = makeVector(state.range(0), mod);
	state.ResumeTiming();

	BigBinaryVector c1 = a+b;
}

static void BM_BBV_Addition(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		add_BBV(state);
	}
}

BENCHMARK(BM_BBV_Addition)->Arg(256)->Arg(512)->Arg(1024)->Arg(2048)->Arg(4096);		// register benchmark

// add
static void mult_BBV(int siz) {	// function
	BigBinaryVector a = makeVector(siz, mod), b = makeVector(siz, mod);
	BigBinaryVector c1 = a*b;
}

static void BM_BBV_Multiplication(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
	mult_BBV(state.range(0));
	}
}

BENCHMARK(BM_BBV_Multiplication)->Arg(256)->Arg(512)->Arg(1024)->Arg(2048)->Arg(4096);		// register benchmark


//execute the benchmarks
BENCHMARK_MAIN()
