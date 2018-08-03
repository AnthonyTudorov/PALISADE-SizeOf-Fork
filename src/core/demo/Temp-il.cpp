/*
 * Temp-il.cpp
 *
 *  Created on: Jul 31, 2018
 *      Author: gwryan
 */

#include <iostream>
#include <string>
#include <map>
using namespace std;

#include "math/backend.h"
#include "utils/serializablehelper.h"

#include "math/nbtheory.cpp"
#include "math/transfrm.cpp"
#include "math/binaryuniformgenerator.cpp"
#include "math/ternaryuniformgenerator.cpp"
#include "math/discreteuniformgenerator.cpp"
#include "math/discretegaussiangenerator.cpp"
#include "lattice/elemparams.cpp"
#include "lattice/ilparams.cpp"
#include "lattice/ildcrtparams.cpp"
#include "lattice/poly.cpp"
#include "lattice/dcrtpoly.cpp"

using namespace lbcrypto;

namespace lbcrypto {

map<string,Format> Formats = {
		{ "EVALUATION", EVALUATION },
		{ "COEFFICIENT", COEFFICIENT },
};

enum PolyType { PTNative, PTInteger, PTDCRT };

enum MathLayer { M2, M4, M6 };

using M2Integer = cpu_int::BigInteger<integral_dtype,BigIntegerBitLength>;
using M2Vector = cpu_int::BigVectorImpl<M2Integer>;

//template class M2Integer;
//template class M2Vector;

using M4Integer = exp_int::xubint;
using M4Vector = exp_int::xmubintvec;

using M6Integer = NTL::myZZ;
using M6Vector = NTL::myVecP<M6Integer>;

template class ElemParams<M2Integer>;
template class ILParamsImpl<M2Integer>;
template class PolyImpl<M2Vector>;

bool ParamMaker( MathLayer ml, PolyType p, void** newParm,
		usint m, uint64_t q, uint64_t ru, uint64_t bq = 0, uint64_t bru = 0)
{
	return false;
}

#define GENERATE_NEW_PARM( PARMTYPE, INTTYPE ) \
		{ \
	auto np = new PARMTYPE<INTTYPE>(m, INTTYPE(q), INTTYPE(ru)); \
	*newParm = (void *)np; \
	return true; \
		}

bool ParamMaker( MathLayer ml, PolyType p, void** newParm,
		usint m, string q, string ru, string bq, string bru)
{
	if( p == PTNative ) {
		GENERATE_NEW_PARM( ILParamsImpl, NativeInteger )
		//		auto np = new ILParamsImpl<NativeInteger>(m, NativeInteger(q), NativeInteger(ru));
		//		*newParm = (void *)np;
		//		return true;
	}

	switch( ml ) {
	case M2:
	{
		if( p == PTInteger ) {
			GENERATE_NEW_PARM( ILParamsImpl, M2Integer )
		}
		else if( p == PTDCRT ) {

		}
		else {
			return false;
		}
	}
	break;

	case M4:
	{
		if( p == PTInteger ) {

		}
		else if( p == PTDCRT ) {

		}
		else {
			return false;
		}
	}
	break;

	case M6:
	{
		if( p == PTInteger ) {

		}
		else if( p == PTDCRT ) {

		}
		else {
			return false;
		}
	}
	break;

	}

	return false;
}

enum GeneratorType { NoGenerator, DiscreteGaussian, BinaryUniform, TernaryUniform, DiscreteUniform };
map<string,GeneratorType> Generators = {
		{ "dgg", DiscreteGaussian },
		{ "bug", BinaryUniform },
		{ "tug", TernaryUniform },
		{ "dug", DiscreteUniform },
};

class PolyFactory {
	static PolyType		pt;
	static MathLayer	ml;
	//static shared_ptr<ElemParams> ep;
	static shared_ptr<ILParams>	parms;

public:
	static void SetPolyType(PolyType p) { pt = p; }
	static void SetMathLayer(MathLayer m) { ml = m; }
	static void SetLatticeParms(shared_ptr<ILParams> lp) { parms = lp; }

	static bool MakePoly(string inputJson, Poly** newPoly) { return MakePoly(pt, ml, inputJson, newPoly); }
	static bool MakePoly(PolyType p, MathLayer m, string inputJson, Poly** newPoly);
};

class B {
public:
	int x;
};

template<typename T>
class C : public B {
	T y;
};

template<typename T2>
class D : public B {
	T2 z;
};

void f() {
	C<int> xxx;
	xxx.x = 1;

	D<char> yyy;
	yyy.x = 2;

	B* xxxp = & xxx;
	B* yyyp = & yyy;

	cout << xxxp->x << yyyp->x;
}

//string PolyFactoryParmSchema =
//		;

bool
PolyFactory::MakePoly(PolyType p, MathLayer m, string inputJson, Poly** newPoly)
{
	Serialized parmsDoc;
	if( SerializableHelper::StringToSerialization(inputJson, &parmsDoc) == false )
		return false;

	Format fmt = EVALUATION;
	auto pkv = parmsDoc.FindMember("format");
	if( pkv != parmsDoc.MemberEnd() ) {
		fmt = Formats[pkv->value.GetString()];
	}

	bool initToZero = false;
	pkv = parmsDoc.FindMember("initToZero");
	if( pkv != parmsDoc.MemberEnd() ) {
		initToZero = true;
	}

	bool initToMax = false;
	pkv = parmsDoc.FindMember("initToMax");
	if( pkv != parmsDoc.MemberEnd() ) {
		initToMax = true;
	}

	GeneratorType gen = NoGenerator;
	pkv = parmsDoc.FindMember("generator");
	if( pkv != parmsDoc.MemberEnd() ) {
		gen = Generators[pkv->value.GetString()];
	}

	if( gen != NoGenerator ) {
		if( initToZero == true || initToMax == true ) {
			// you can't use a generator AND say init to 0 or max
			return false;
		}
	}

	if( initToZero == true && initToMax == true ) {
		// you can't have it both ways
		return false;
	}

	switch( m ) {
	case M2:
	{
		switch( p ) {
		case PTNative:
		{

		}
		break;

		case PTInteger:
		{

		}
		break;

		case PTDCRT:
		{

		}
		break;
		}
	}
	break;

	case M4:
	{
		switch( p ) {
		case PTNative:
		{

		}
		break;

		case PTInteger:
		{

		}
		break;

		case PTDCRT:
		{

		}
		break;
		}
	}
	break;

	case M6:
	{
		switch( p ) {
		case PTNative:
		{

		}
		break;

		case PTInteger:
		{
			*newPoly = new PolyImpl<BigVector>(parms, fmt, initToZero);
		}
		break;

		case PTDCRT:
		{

		}
		break;
		}
	}
	break;

	}

	return true;
}

PolyType PolyFactory::pt = PTInteger;
MathLayer PolyFactory::ml = M6;
shared_ptr<ILParams>	PolyFactory::parms;

}


template<typename I>
class myParms {
public:
	typedef I Integer;

	Integer x;
};

template<typename I>
class myILParms : public myParms<I> {
public:
	typename myParms<I>::Integer y;
};

template<typename I>
class myILDCRTParms : public myParms<I> {
public:
	typename myParms<I>::Integer z[3];
};

template<typename I>
class Vector {
public:
	typedef I Integer;

	I	foo, bar;
};

template<typename V>
class MyPoly {
public:
	typedef typename V::Integer Integer;
	typedef V Vector;
	typedef myILParms<Integer> Parms;

	MyPoly( Parms *p ) : pptr(p) {}

	Vector x;

private:
	Parms *pptr;
};

int
main(int argc, char *argv[])
{
	myILParms<int> mp;
	MyPoly<Vector<int>> p( &mp );

	p.x.foo = p.x.bar = 127;
	cout << "Hello" << endl;

	usint m = 8;
	BigInteger q("73");
	BigInteger primitiveRootOfUnity("22");
	BigInteger ptm("8");

	shared_ptr<ILParams> ilparams( new ILParams(m, q, primitiveRootOfUnity) );

	PolyFactory::SetLatticeParms(ilparams);

	Poly *poly;
	if( PolyFactory::MakePoly("{}",&poly) ) {
		cout << "Poly Success!" << endl;
	}

	return 0;
}
