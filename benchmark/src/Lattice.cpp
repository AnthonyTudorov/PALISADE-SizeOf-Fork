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
#if 1
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
#endif


using namespace std;
using namespace lbcrypto;

#define BASIC_BENCHMARK_TEST(x) \
    BENCHMARK(x)->Arg(0)->Arg(1)->Arg(2)->Arg(4)->Arg(8)->Arg(16)

static void make_LATTICE_constants(void) {
	ILVector2n v;
}

void BM_LATTICE_constants(benchmark::State& state) { // benchmark
  while (state.KeepRunning()) {
	  make_LATTICE_constants();
  }
}

BASIC_BENCHMARK_TEST(BM_LATTICE_constants);		// register benchmark

// make variables

static void make_BBI_small_variables (void) {	// function
	BigBinaryInteger zero(BigBinaryInteger::ZERO);
	BigBinaryInteger a("10403"), b("103");
}


  void BM_BBI_small_variables(benchmark::State& state) { // benchmark
  while (state.KeepRunning()) {
    make_BBI_small_variables();		// note even with -O3 it appears
                                // this is not optimized out
                                // though check with your compiler
  }
}

BENCHMARK(BM_BBI_small_variables);		// register benchmark


static void make_BBI_large_variables (void) {	// function
	BigBinaryInteger one(BigBinaryInteger::ONE);
	BigBinaryInteger a("18446744073709551616"), b("18446744073709551617");
	BigBinaryInteger total = b-a;

	  if (total != one)
	  cout << "should be one: "<<total<<endl;

}

  void BM_BBI_large_variables(benchmark::State& state) { // benchmark
  while (state.KeepRunning()) {
    make_BBI_large_variables();		// note even with -O3 it appears
                                // this is not optimized out
                                // though check with your compiler
  }
}

BENCHMARK(BM_BBI_large_variables);		// register benchmark



// add
static void add_BBI(void) {	// function
	BigBinaryInteger zero(BigBinaryInteger::ZERO);
  BigBinaryInteger a("10403"), b("103");
  BigBinaryInteger c1 = a+b;
  BigBinaryInteger c2 = a.Plus(b);

  BigBinaryInteger total = c1 - c2;

  if (total != zero)
	  cout << "should be zero: "<<total<<endl;

}

static void BM_BBI2(benchmark::State& state) { // benchmark

  while (state.KeepRunning()) {
   add_BBI();
  }
}

BENCHMARK(BM_BBI2);		// register benchmark

//execute the benchmarks
BENCHMARK_MAIN()
