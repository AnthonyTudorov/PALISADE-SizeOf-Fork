/*
 * Temp-cereal.cpp
 *
 *  Created on: Jan 4, 2018
 *      Author: gerardryan
 */

#include "palisade.h"
#include "cryptocontext.h"
using namespace lbcrypto;

int
main()
{
	NativeInteger foo = 12;
	{
		cereal::JSONOutputArchive archive( cout );
		archive( foo );
	}

	EncodingParams ep( new EncodingParamsImpl(373) );

//	{
//		cereal::JSONOutputArchive archive( cout );
//
//		cout << "before" << endl;
//		archive( *ep );
//		cout << "***after" << endl;
//	}

	return 0;
}


