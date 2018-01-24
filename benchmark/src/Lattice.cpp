/*
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 */
/*

  Description:
  This code benchmarks functions of the src/lib/lattoce directory  of the PALISADE lattice encryption library.
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
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "../../src/core/lib/lattice/dcrtpoly.h"
#include "utils/utilities.h"

#include <vector>

#include "vechelper.h"
#include "ElementParmsHelper.h"

#include "lattice/elemparams.cpp"
#include "lattice/ilparams.cpp"
#include "lattice/ildcrtparams.cpp"
#include "lattice/poly.cpp"
#include "lattice/dcrtpoly.cpp"
#include "math/nbtheory.cpp"
#include "math/transfrm.cpp"
#include "math/discreteuniformgenerator.cpp"
#include "math/discretegaussiangenerator.cpp"

using namespace std;
using namespace lbcrypto;

template <typename E>
static E makeElement(shared_ptr<lbcrypto::ILParamsImpl<typename E::Integer>> params) {
	typename E::Vector	vec = makeVector<E>(params);
	E					elem(params);

	elem.SetValues(vec, elem.GetFormat());
	return std::move(elem);
}

template <typename E>
static E makeElement(shared_ptr<lbcrypto::ILDCRTParams<typename E::Integer>> p) {
	shared_ptr<ILParamsImpl<typename E::Integer>>	params( new ILParamsImpl<typename E::Integer>( p->GetCyclotomicOrder(), p->GetModulus(), 1) );
	typename E::Vector								vec = makeVector<typename E::PolyLargeType>(params);

	typename E::PolyLargeType	bigE(params);
	bigE.SetValues(vec, bigE.GetFormat());

	E			elem(bigE, p);
	return std::move(elem);
}

static vector<usint> o( { 16, 1024, 2048, 4096, 8192, 16384, 32768 } );

template<typename P, typename I>
static void GenerateParms(map<usint,shared_ptr<P>>& parmArray) {

	for(usint v : o ) {
		parmArray[v] = ElemParamFactory::GenElemParams<P,I>(v);
	}
}

template<typename P, typename I>
static void GenerateDCRTParms(map<usint,shared_ptr<P>>& parmArray) {

	for(usint v : o ) {
		parmArray[v] = ElemParamFactory::GenElemParams<P,I>(v, 28, 5);
	}
}

template<typename P, typename E>
static void GeneratePolys(map<usint,shared_ptr<P>>& parmArray, map<usint,vector<E>>& polyArray) {
	for( usint v : o ) {
		for( int i=0; i<2; i++ )
			polyArray[v].push_back( makeElement<E>(parmArray[v]) );
	}
}

using BE2Integer = cpu_int::BigInteger<integral_dtype,BigIntegerBitLength>;
using BE2ILParams = ILParamsImpl<BE2Integer>;
using BE2ILDCRTParams = ILDCRTParams<BE2Integer>;
using BE2Vector = cpu_int::BigVectorImpl<BE2Integer>;
using BE2Poly = PolyImpl<BE2Integer, BE2Integer, BE2Vector, BE2ILParams>;
using BE2DCRTPoly = DCRTPolyImpl<BE2Integer, BE2Integer, BE2Vector, BE2ILDCRTParams>;

using BE4Integer = exp_int::xubint;
using BE4ILParams = ILParamsImpl<BE4Integer>;
using BE4ILDCRTParams = ILDCRTParams<BE4Integer>;
using BE4Vector = exp_int::xmubintvec;
using BE4Poly = PolyImpl<BE4Integer, BE4Integer, BE4Vector, BE4ILParams>;
using BE4DCRTPoly = DCRTPolyImpl<BE4Integer, BE4Integer, BE4Vector, BE4ILDCRTParams>;

using BE6Integer = NTL::myZZ;
using BE6ILParams = ILParamsImpl<BE6Integer>;
using BE6ILDCRTParams = ILDCRTParams<BE6Integer>;
using BE6Vector = NTL::myVecP<NTL::myZZ>;
using BE6Poly = PolyImpl<BE6Integer, BE6Integer, BE6Vector, BE6ILParams>;
using BE6DCRTPoly = DCRTPolyImpl<BE6Integer, BE6Integer, BE6Vector, BE6ILDCRTParams>;

//template<>
//inline NativePoly
//PolyImpl<BE2Integer, BE2Integer, BE2Vector, BE2ILParams>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
//	PolyImpl<BE2Integer, BE2Integer, BE2Vector, BE2ILParams> smaller = this->Mod(ptm);
//	NativePoly interp(
//			shared_ptr<ILNativeParams>( new ILNativeParams(this->GetCyclotomicOrder(), ptm, 1) ),
//															this->GetFormat(), true);
//
//	for (usint i = 0; i<smaller.GetLength(); i++) {
//		interp[i] = smaller[i].ConvertToInt();
//	}
//
//	return std::move( interp );
//}

template<>
inline NativePoly
PolyImpl<BE4Integer, BE4Integer, BE4Vector, BE4ILParams>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
	PolyImpl<BE4Integer, BE4Integer, BE4Vector, BE4ILParams> smaller = this->Mod(ptm);
	NativePoly interp(
			shared_ptr<ILNativeParams>( new ILNativeParams(this->GetCyclotomicOrder(), ptm, 1) ),
															this->GetFormat(), true);

	for (usint i = 0; i<smaller.GetLength(); i++) {
		interp[i] = smaller[i].ConvertToInt();
	}

	return std::move( interp );
}

template<>
inline NativePoly
PolyImpl<BE6Integer, BE6Integer, BE6Vector, BE6ILParams>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
	PolyImpl<BE6Integer, BE6Integer, BE6Vector, BE6ILParams> smaller = this->Mod(ptm);
	NativePoly interp(
			shared_ptr<ILNativeParams>( new ILNativeParams(this->GetCyclotomicOrder(), ptm, 1) ),
															this->GetFormat(), true);

	for (usint i = 0; i<smaller.GetLength(); i++) {
		interp[i] = smaller[i].ConvertToInt();
	}

	return std::move( interp );
}


map<usint,shared_ptr<BE2ILParams>> BE2parms;
map<usint,shared_ptr<BE2ILDCRTParams>> BE2dcrtparms;
map<usint,shared_ptr<BE4ILParams>> BE4parms;
map<usint,shared_ptr<BE4ILDCRTParams>> BE4dcrtparms;
map<usint,shared_ptr<BE6ILParams>> BE6parms;
map<usint,shared_ptr<BE6ILDCRTParams>> BE6dcrtparms;
map<usint,vector<BE2Poly>> BE2polys;
map<usint,vector<BE2DCRTPoly>> BE2DCRTpolys;
map<usint,vector<BE4Poly>> BE4polys;
map<usint,vector<BE4DCRTPoly>> BE4DCRTpolys;
map<usint,vector<BE6Poly>> BE6polys;
map<usint,vector<BE6DCRTPoly>> BE6DCRTpolys;

class Setup {
public:
	Setup() {
		GenerateParms<BE2ILParams,BE2Integer>( BE2parms );
		GenerateDCRTParms<BE2ILDCRTParams,BE2Integer>( BE2dcrtparms );
		GenerateParms<BE4ILParams,BE4Integer>( BE4parms );
		GenerateDCRTParms<BE4ILDCRTParams,BE4Integer>( BE4dcrtparms );
		GenerateParms<BE6ILParams,BE6Integer>( BE6parms );
		GenerateDCRTParms<BE6ILDCRTParams,BE6Integer>( BE6dcrtparms );
		GeneratePolys<BE2ILParams,BE2Poly>(BE2parms, BE2polys);
		GeneratePolys<BE4ILParams,BE4Poly>(BE4parms, BE4polys);
		GeneratePolys<BE6ILParams,BE6Poly>(BE6parms, BE6polys);
		GeneratePolys<BE2ILDCRTParams,BE2DCRTPoly>(BE2dcrtparms, BE2DCRTpolys);
		GeneratePolys<BE4ILDCRTParams,BE4DCRTPoly>(BE4dcrtparms, BE4DCRTpolys);
		GeneratePolys<BE6ILDCRTParams,BE6DCRTPoly>(BE6dcrtparms, BE6DCRTpolys);

		cout << *BE2dcrtparms[16] << endl;
		cout << *BE4dcrtparms[16] << endl;
		cout << *BE6dcrtparms[16] << endl;
		cout << BE6DCRTpolys[16][0] << endl;
	}

	template<typename P>
	shared_ptr<P> GetParm(usint o);

	template<typename E>
	const E& GetPoly(usint o, int p);
} TestParameters;

template<>
shared_ptr<BE2ILParams> Setup::GetParm(usint o) { return BE2parms[o]; }

template<>
shared_ptr<BE2ILDCRTParams> Setup::GetParm(usint o) { return BE2dcrtparms[o]; }

template<>
shared_ptr<BE4ILParams> Setup::GetParm(usint o) { return BE4parms[o]; }

template<>
shared_ptr<BE4ILDCRTParams> Setup::GetParm(usint o) { return BE4dcrtparms[o]; }

template<>
shared_ptr<BE6ILParams> Setup::GetParm(usint o) { return BE6parms[o]; }

template<>
shared_ptr<BE6ILDCRTParams> Setup::GetParm(usint o) { return BE6dcrtparms[o]; }

template<> const BE2Poly& Setup::GetPoly(usint o, int p) { return BE2polys[o][p]; }
template<> const BE4Poly& Setup::GetPoly(usint o, int p) { return BE4polys[o][p]; }
template<> const BE6Poly& Setup::GetPoly(usint o, int p) { return BE6polys[o][p]; }
template<> const BE2DCRTPoly& Setup::GetPoly(usint o, int p) { return BE2DCRTpolys[o][p]; }
template<> const BE4DCRTPoly& Setup::GetPoly(usint o, int p) { return BE4DCRTpolys[o][p]; }
template<> const BE6DCRTPoly& Setup::GetPoly(usint o, int p) { return BE6DCRTpolys[o][p]; }

//// test scenarios
//struct Scenario {
//	usint bits;
//	usint m;
//	string modulus;
//	string rootOfUnity;
//} Scenarios[] = {
//		{
//				503,
//				2048,
//				"13093562431584567480052758787310396608866568184172259157933165472384535185618698219533080369303616628603546736510240284036869026183541572213314110873601",
//				"12023848463855649466660377440069556144464267030949365165993725942220441412632799311989973938254823071405336623315668961501139592673000297887682895033094"
//		},
//		{
//				132,
//				8192,
//				"2722258935367507707706996859454146142209",
//				"1426115470453457649704739287701063827541"
//		},
//};
//
//template<typename P,typename I>
//static shared_ptr<P> generate_IL_parms(int s) {
//	return shared_ptr<P>( new P(Scenarios[s].m, I(Scenarios[s].modulus), I(Scenarios[s].rootOfUnity)) );
//}
//
//static const usint smbits = 28;
//
//template<typename I>
//static shared_ptr<ILDCRTParams<I>> generate_DCRT_parms(int s) {
//	usint nTowers = Scenarios[s].bits/smbits;
//
//	vector<NativeInteger> moduli(nTowers);
//	vector<NativeInteger> rootsOfUnity(nTowers);
//
//	NativeInteger q = FirstPrime<NativeInteger>(smbits, Scenarios[s].m);
//	NativeInteger temp;
//	I modulus(1);
//
//	for(usint i=0; i < nTowers; i++){
//		moduli[i] = q;
//		rootsOfUnity[i] = RootOfUnity(Scenarios[s].m,moduli[i]);
//		modulus = modulus * I(moduli[i]);
//		q = NextPrime(q, Scenarios[s].m);
//	}
//
//	return shared_ptr<ILDCRTParams<I>>( new ILDCRTParams<I>(Scenarios[s].m, moduli, rootsOfUnity) );
//}

template <typename E>
static void make_LATTICE_empty(shared_ptr<typename E::Params> params) {
	E v1(params);
}

template <typename E>
void BM_LATTICE_empty(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		make_LATTICE_empty<E>(TestParameters.GetParm<typename E::Params>(state.range(0)));
	}
}

#define DO_POLY_BENCHMARK_TEMPLATE(X,Y) \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16")->Arg(16); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024")->Arg(1024); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048")->Arg(2048); \
		/*BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096")->Arg(4096);*/ \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192")->Arg(8192); \
		/*BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16384")->Arg(16384);*/ \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32768")->Arg(32768);

DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_empty,BE6DCRTPoly)

template <typename E>
static void make_LATTICE_vector (benchmark::State& state, shared_ptr<typename E::Params> params) {	// function
	E	elem = makeElement<E>(params);
}

template <typename E>
void BM_LATTICE_makevector(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		make_LATTICE_vector<E>(state, TestParameters.GetParm<typename E::Params>(state.range(0)));
	}
}

DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_LATTICE_makevector,BE6DCRTPoly)

// plus
template <typename E>
static void add_LATTICE(const E& a, const E& b) {

	E c1;
	benchmark::DoNotOptimize(c1 = a+b);
}

template <typename E>
static void BM_add_LATTICE(benchmark::State& state) { // benchmark
	E a;
	E b;

	if( state.thread_index == 0 ) {
		a = TestParameters.GetPoly<E>(state.range(0),0);
		b = TestParameters.GetPoly<E>(state.range(0),1);
	}

	while (state.KeepRunning()) {
		add_LATTICE<E>(a, b);
	}
}

DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_add_LATTICE,BE6DCRTPoly)

// plus=
template <typename E>
static void addeq_LATTICE(E& a, const E& b) {

	benchmark::DoNotOptimize(a += b);
}

template <typename E>
static void BM_addeq_LATTICE(benchmark::State& state) { // benchmark
	E a;
	E b;

	if( state.thread_index == 0 ) {
		b = TestParameters.GetPoly<E>(state.range(0),1);
	}

	while (state.KeepRunning()) {
		a = TestParameters.GetPoly<E>(state.range(0),0);
		addeq_LATTICE<E>(a,b);
	}
}

DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_addeq_LATTICE,BE6DCRTPoly)

template <class E>
static void mult_LATTICE(const E& a, const E& b) {	// function

	E c1;
	benchmark::DoNotOptimize(c1 = a*b);
}

template <class E>
static void BM_mult_LATTICE(benchmark::State& state) {
	E a,b;

	if( state.thread_index == 0 ) {
		a = TestParameters.GetPoly<E>(state.range(0),0);
		b = TestParameters.GetPoly<E>(state.range(0),1);
	}

	while (state.KeepRunning()) {
		mult_LATTICE<E>(a, b);
	}
}

DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_mult_LATTICE,BE6DCRTPoly)

template <class E>
static void multeq_LATTICE(E& a, const E& b) {	// function

	benchmark::DoNotOptimize(a *= b);
}

template <class E>
static void BM_multeq_LATTICE(benchmark::State& state) { // benchmark
	E a,b;

	if( state.thread_index == 0 ) {
		b = TestParameters.GetPoly<E>(state.range(0),1);
	}

	while (state.KeepRunning()) {
		a = TestParameters.GetPoly<E>(state.range(0),0);
		multeq_LATTICE<E>(a, b);
	}
}

DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_multeq_LATTICE,BE6DCRTPoly)

template <class E>
static void switchformat_LATTICE(benchmark::State& state, shared_ptr<typename E::Params> params) {
	state.PauseTiming();
	E			a = makeElement<E>(params);
	state.ResumeTiming();

	a.SwitchFormat();
}

template <class E>
static void BM_switchformat_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		switchformat_LATTICE<E>(state, TestParameters.GetParm<typename E::Params>(state.range(0)));
	}
}

DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,BE6DCRTPoly)

template <class E>
static void doubleswitchformat_LATTICE(benchmark::State& state, shared_ptr<typename E::Params> params) {
	state.PauseTiming();
	E			a = makeElement<E>(params);
	state.ResumeTiming();

	a.SwitchFormat();
	a.SwitchFormat();
}

template <class E>
static void BM_doubleswitchformat_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		doubleswitchformat_LATTICE<E>(state, TestParameters.GetParm<typename E::Params>(state.range(0)));
	}
}

DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE,BE2Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE,BE4Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE,BE6Poly)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE,BE2DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE,BE4DCRTPoly)
DO_POLY_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE,BE6DCRTPoly)

//execute the benchmarks
BENCHMARK_MAIN()
