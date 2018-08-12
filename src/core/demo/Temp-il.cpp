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

/**
 * ParamMaker
 * @param ml
 * @param p
 * @param m
 * @param q as a string
 */
void *ParamMaker( MathLayer ml, PolyType p, usint m, string q ) {

	if( p == PTNative )
		return (void *) new ILParamsImpl<NativeInteger>( m, NativeInteger(q) );

	if( p == PTDCRT )
		return 0;

	switch( ml ) {
	case M2:
		return (void *) new ILParamsImpl<M2Integer>( m, M2Integer(q) );

	case M4:
		return (void *) new ILParamsImpl<M4Integer>( m, M4Integer(q) );

	case M6:
		return (void *) new ILParamsImpl<M6Integer>( m, M6Integer(q) );

	}

	return 0;
}

void *ParamMaker( MathLayer ml, PolyType p, usint m, usint q ) {
	return ParamMaker( ml, p, m, to_string(q) );
}

#define GENERATE_NEW_PARM( PARMTYPE, INTTYPE ) { return new PARMTYPE<INTTYPE>(m, INTTYPE(q), INTTYPE(ru), INTTYPE(bq), INTTYPE(bru)); }

void *ParamMaker( MathLayer ml, PolyType p, usint m, string q, string ru, string bq = "0", string bru = "0") {

	if( p == PTNative )
		GENERATE_NEW_PARM( ILParamsImpl, NativeInteger )
	if( p == PTDCRT )
		return 0;

	switch( ml ) {
	case M2:
		GENERATE_NEW_PARM( ILParamsImpl, M2Integer )

	case M4:
		GENERATE_NEW_PARM( ILParamsImpl, M4Integer )

	case M6:
		GENERATE_NEW_PARM( ILParamsImpl, M6Integer )

	}

	return 0;
}

void *ParamMaker( MathLayer ml, PolyType pt, usint m,
		vector<NativeInteger> q, vector<NativeInteger> ru, vector<NativeInteger> bq, vector<NativeInteger> bru) {
	if( pt != PTDCRT ) {
		// error
	}

	switch( ml ) {
	case M2:
		return (void *) new ILDCRTParams<M2Integer>( m, q, ru, bq, bru );

	case M4:
		return (void *) new ILDCRTParams<M4Integer>( m, q, ru, bq, bru );

	case M6:
		return (void *) new ILDCRTParams<M6Integer>( m, q, ru, bq, bru );

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
	static PolyType		default_pt;
	static MathLayer		default_ml;
	static void			*default_parm;

public:
	static void SetPolyType(PolyType p) { default_pt = p; }
	static void SetMathLayer(MathLayer m) { default_ml = m; }
	static void SetParm(void *pp) { default_parm = pp; }

	static void *MakePoly(string inputJson) { return MakePoly(default_pt, default_ml, inputJson); }
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
			shared_ptr<M6Params> parm((M6Params *)default_parm);
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

PolyType PolyFactory::default_pt = PTInteger;
MathLayer PolyFactory::default_ml = M6;
void *PolyFactory::default_parm = 0;

}

int
main(int argc, char *argv[])
{
	cout << "Hello" << endl;

	usint m = 8;
	string q("73");
	string ru("22");
//	PlaintextModulus ptm = 8;

	PolyFactory::SetMathLayer(M6);
	PolyFactory::SetPolyType(PTInteger);

	ILParams *np;

	np = (ILParams *)ParamMaker( M6, PTInteger, m, q, ru );
	PolyFactory::SetParm(np);

	cout << "Made parm" << endl;
	cout << *np << endl;

	Poly *poly = (Poly *)PolyFactory::MakePoly("{}");
	if( poly ) {
		cout << "Poly Success!" << endl;
	}

	return 0;
}
