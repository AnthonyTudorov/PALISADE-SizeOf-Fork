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

bool ParamMaker( MathLayer ml, PolyType p,
		usint m, uint64_t q, uint64_t ru, uint64_t bq = 0, uint64_t bru = 0)
{
	return false;
}

#define GENERATE_NEW_PARM( PARMTYPE, INTTYPE ) { return new PARMTYPE<INTTYPE>(m, INTTYPE(q), INTTYPE(ru)); }

void *ParamMaker( MathLayer ml, PolyType p,
		usint m, string q, string ru, string bq = "0", string bru = "0")
{
	if( p == PTNative ) {
		GENERATE_NEW_PARM( ILParamsImpl, NativeInteger )
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
			return 0;
		}
	}
	break;

	case M4:
	{
		if( p == PTInteger ) {
			GENERATE_NEW_PARM( ILParamsImpl, M4Integer )
		}
		else if( p == PTDCRT ) {

		}
		else {
			return 0;
		}
	}
	break;

	case M6:
	{
		if( p == PTInteger ) {
			GENERATE_NEW_PARM( ILParamsImpl, M6Integer )
		}
		else if( p == PTDCRT ) {

		}
		else {
			return 0;
		}
	}
	break;

	}

	return 0;
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
	static MathLayer		ml;

public:
	static void SetPolyType(PolyType p) { pt = p; }
	static void SetMathLayer(MathLayer m) { ml = m; }

	static void *MakePoly(string inputJson) { return MakePoly(pt, ml, inputJson); }
	static void *MakePoly(PolyType p, MathLayer m, string inputJson);
};


//string PolyFactoryParmSchema =
//		;

void *
PolyFactory::MakePoly(PolyType p, MathLayer m, string inputJson)
{
	Serialized parmsDoc;
	if( SerializableHelper::StringToSerialization(inputJson, &parmsDoc) == false )
		return 0;

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
			return 0;
		}
	}

	if( initToZero == true && initToMax == true ) {
		// you can't have it both ways
		return 0;
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
			shared_ptr<M6Params> parm;
			return new M6Poly(parm, fmt, initToZero);
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

	return 0;
}

PolyType PolyFactory::pt = PTInteger;
MathLayer PolyFactory::ml = M6;

}

int
main(int argc, char *argv[])
{
	cout << "Hello" << endl;

	usint m = 8;
	string q("73");
	string ru("22");
//	PlaintextModulus ptm = 8;

	ILParams *np;

	np = (ILParams *)ParamMaker( M6, PTInteger, m, q, ru );

	Poly *poly = (Poly *)PolyFactory::MakePoly("{}");
	if( poly ) {
		cout << "Poly Success!" << endl;
	}

	return 0;
}
