/**
* @file
* @author	TPOC:
				Dr. Kurt Rohloff <rohloff@njit.edu>,
			Programmers:
				Jerry Ryan <gwryan@njit.edu>

* @version 00_03
*
* @section LICENSE
*
* Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
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
* @section DESCRIPTION
*
* This file implements a helper class for managing and manipulating Crypto Contexts
*/

#include "../palisade.h"
#include "../palisadespace.h"

#include "../crypto/cryptocontext.h"
#include "../utils/cryptocontexthelper.h"
#include "../../../include/rapidjson/filewritestream.h"

namespace lbcrypto {

static bool
getValueForName(const map<string,string>& allvals, const string key, string& value)
{
	map<string,string>::const_iterator it = allvals.find(key);
	if( it == allvals.end() ) {
		std::cerr << key << " element is missing" << std::endl;
		return false;
	}

	value = it->second;
	return true;
}

template <class Element>
static CryptoContext<Element>
buildContextFromSerialized(const map<string,string>& s)
{
	std::string parmtype;
	std::string plaintextModulus;
	std::string ring;
	std::string modulus;
	std::string rootOfUnity;
	std::string relinWindow;
	std::string stDev;
	std::string stDevStSt;

	if( !getValueForName(s, "parameters", parmtype) ) {
		std::cerr << "parameters element is missing" << std::endl;
		return 0;
	}

	if( parmtype == "LTV" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ||
				!getValueForName(s, "ring", ring) ||
				!getValueForName(s, "modulus", modulus) ||
				!getValueForName(s, "rootOfUnity", rootOfUnity) ||
				!getValueForName(s, "relinWindow", relinWindow) ||
				!getValueForName(s, "stDev", stDev) ) {
			return 0;
		}

		return CryptoContextFactory<Element>::genCryptoContextLTV(stoul(plaintextModulus), stoul(ring),
				modulus, rootOfUnity, stoul(relinWindow), stof(stDev));
	}
	else if( parmtype == "StehleSteinfeld" ) {
		if( !getValueForName(s, "plaintextModulus", plaintextModulus) ||
				!getValueForName(s, "ring", ring) ||
				!getValueForName(s, "modulus", modulus) ||
				!getValueForName(s, "rootOfUnity", rootOfUnity) ||
				!getValueForName(s, "relinWindow", relinWindow) ||
				!getValueForName(s, "stDev", stDev) ||
				!getValueForName(s, "stDevStSt", stDevStSt) ) {
			return 0;
		}

		return CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(stoul(plaintextModulus), stoul(ring),
				modulus, rootOfUnity, stoul(relinWindow), stof(stDev), stof(stDevStSt));
	}
	else if( parmtype == "Null" ) {
		return CryptoContextFactory<Element>::getCryptoContextNull();
	}

	return 0;
}

template <class Element>
CryptoContext<Element>
CryptoContextHelper<Element>::getNewContextFromSerialization(const Serialized& ser)
{
	LPCryptoParameters<Element>* cParams = DeserializeCryptoParameters<Element>(ser);

	if( cParams == 0 ) return 0;

	const ILParams& ep = dynamic_cast<const ILParams&>(cParams->GetElementParams());

	// see what kind of parms we have here...
	LPCryptoParametersLTV<Element> *ltvp = dynamic_cast<LPCryptoParametersLTV<Element> *>(cParams);
	LPCryptoParametersStehleSteinfeld<Element> *ststp = dynamic_cast<LPCryptoParametersStehleSteinfeld<Element> *>(cParams);

	if( ststp != 0 ){
		return CryptoContextFactory<Element>::genCryptoContextStehleSteinfeld(cParams->GetPlaintextModulus().ConvertToInt(), ep.GetCyclotomicOrder(),
				ep.GetModulus().ToString(), ep.GetRootOfUnity().ToString(), ststp->GetRelinWindow(), ststp->GetDistributionParameter(), ststp->GetDistributionParameterStSt());
	}
	else if( ltvp != 0 ) {
		return CryptoContextFactory<Element>::genCryptoContextLTV(cParams->GetPlaintextModulus().ConvertToInt(), ep.GetCyclotomicOrder(),
				ep.GetModulus().ToString(), ep.GetRootOfUnity().ToString(), ltvp->GetRelinWindow(), ltvp->GetDistributionParameter());
	}

	// empty one
	CryptoContext<Element> newCtx;
	return newCtx;
}

template <class Element>
CryptoContext<Element>
CryptoContextHelper<Element>::getNewContext(const string parmset)
{
	map<string, map<string,string>>::iterator it = CryptoContextParameterSets.find(parmset);

	if( it == CryptoContextParameterSets.end() ) {
		return 0;
	}

	return buildContextFromSerialized<Element>(it->second);
}

static void printSet(std::ostream& out, string key, map<string,string>& pset)
{
	out << "Parameter set: " << key << std::endl;

	for( auto P : pset ) {
		out << "  " << P.first << ": " << P.second << std::endl;
	}
}

template <class Element>
void
CryptoContextHelper<Element>::printParmSet(std::ostream& out, string parmset)
{
	auto it = CryptoContextParameterSets.find(parmset);
	if( it == CryptoContextParameterSets.end() ) {
		out << "Parameter set " << parmset << " is unknown" << std::endl;
	}
	else
		printSet(out, it->first, it->second);

}


template <class Element>
void
CryptoContextHelper<Element>::printAllParmSets(std::ostream& out)
{
	for( auto S : CryptoContextParameterSets ) {
		printSet(out, S.first, S.second);
	}
}

template <class Element>
void
CryptoContextHelper<Element>::printAllParmSetNames(std::ostream& out)
{
	map<string, map<string,string>>::iterator it = CryptoContextParameterSets.begin();

	out << it->first;

	for( it++; it != CryptoContextParameterSets.end(); it++ ) {
		out << ", " << it->first;
	}
	out << std::endl;
}

}
