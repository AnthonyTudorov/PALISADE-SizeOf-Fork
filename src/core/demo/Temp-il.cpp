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

using namespace lbcrypto;

namespace lbcrypto {

map<string,Format> Formats = {
		{ "EVALUATION", EVALUATION },
		{ "COEFFICIENT", COEFFICIENT },
};

enum PolyType { PTNative, PTInteger, PTDCRT };

enum MathLayer { M2, M4, M6 };

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
	static shared_ptr<ILParams>	parms;

public:
	static void SetPolyType(PolyType p) { pt = p; }
	static void SetMathLayer(MathLayer m) { ml = m; }
	static void SetLatticeParms(shared_ptr<ILParams> lp) { parms = lp; }

	static bool MakePoly(string inputJson, Poly** newPoly) { return MakePoly(pt, ml, inputJson, newPoly); }
	static bool MakePoly(PolyType p, MathLayer m, string inputJson, Poly** newPoly);
};

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
	cout << fmt << endl;

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
			//*newPoly = new Poly<x>(parms, fmt, initToZero);
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
	return 0;
}
