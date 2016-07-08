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

#include "../crypto/cryptocontext.h"
#include "../utils/cryptocontexthelper.h"
#include "../../../include/rapidjson/filewritestream.h"

namespace lbcrypto {

static bool
getParmsFile(const std::string& fn, Serialized* obj)
{
	return SerializableHelper::ReadSerializationFromFile(fn, obj);
}

static bool
getValueForName(const SerialItem& allvals, const char *key, std::string& value)
{
	Serialized::ConstMemberIterator it;
	if( (it = allvals.FindMember(key)) == allvals.MemberEnd() ) {
		std::cerr << key << " element is missing" << std::endl;
		return false;
	}

	value = it->value.GetString();
	return true;
}

template <class Element>
static CryptoContext<Element> *
buildContextFromSerialized(const SerialItem& s)
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

		return CryptoContext<Element>::genCryptoContextLTV(stoul(plaintextModulus), stoul(ring),
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

		return CryptoContext<Element>::genCryptoContextStehleSteinfeld(stoul(plaintextModulus), stoul(ring),
				modulus, rootOfUnity, stoul(relinWindow), stof(stDev), stof(stDevStSt));
	}

	return 0;
}

template <class Element>
CryptoContext<Element> *
CryptoContextHelper<Element>::getNewContextFromSerialization(const Serialized& ser)
{
	LPCryptoParameters<Element>* cParams = DeserializeCryptoParameters<Element>(ser);

	if( cParams == 0 ) return 0;

	CryptoContext<Element>* newCtx = 0;

	const ILParams& ep = dynamic_cast<const ILParams&>(cParams->GetElementParams());

	// see what kind of parms we have here...
	LPCryptoParametersLTV<Element> *ltvp = dynamic_cast<LPCryptoParametersLTV<Element> *>(cParams);
	LPCryptoParametersStehleSteinfeld<Element> *ststp = dynamic_cast<LPCryptoParametersStehleSteinfeld<Element> *>(cParams);

	if( ststp != 0 ){
		newCtx = CryptoContext<Element>::genCryptoContextStehleSteinfeld(cParams->GetPlaintextModulus().ConvertToInt(), ep.GetCyclotomicOrder(),
				ep.GetModulus().ToString(), ep.GetRootOfUnity().ToString(), ststp->GetRelinWindow(), ststp->GetDistributionParameter(), ststp->GetDistributionParameterStSt());
	}
	else if( ltvp != 0 ) {
		newCtx = CryptoContext<Element>::genCryptoContextLTV(cParams->GetPlaintextModulus().ConvertToInt(), ep.GetCyclotomicOrder(),
				ep.GetModulus().ToString(), ep.GetRootOfUnity().ToString(), ltvp->GetRelinWindow(), ltvp->GetDistributionParameter());
	}

	delete ltvp;
	return newCtx;
}


template <class Element>
CryptoContext<Element> *
CryptoContextHelper<Element>::getNewContext(const std::string& parmSetJson)
{
	// convert string to a map
	Serialized sObj;
	sObj.Parse( parmSetJson.c_str() );
	if( sObj.HasParseError() )
		return 0;
	return buildContextFromSerialized<Element>(sObj);
}

template <class Element>
CryptoContext<Element> *
CryptoContextHelper<Element>::getNewContext(const std::string& parmfile, const std::string& parmset)
{
	Serialized sobj;

	if( !getParmsFile(parmfile, &sobj) ) {
		std::cerr << "Unable to read serialization from " << parmfile << std::endl;
		return 0;
	}

	Serialized::ConstMemberIterator it;
	for( it = sobj.MemberBegin(); it != sobj.MemberEnd(); it++ ) {
		if( parmset != it->name.GetString() )
			continue;

		break;
	}

	if( it == sobj.MemberEnd() )
		return 0;

	const SerialItem& cObj = it->value;
	return buildContextFromSerialized<Element>(cObj);
}

template <class Element>
void
CryptoContextHelper<Element>::printAllParmSets(std::ostream& out, const std::string& fn)
{
	Serialized sobj;

	if( !getParmsFile(fn, &sobj) ) {
		out << "Unable to read serialization from " << fn << std::endl;
		return;
	}

	for( Serialized::ConstMemberIterator it = sobj.MemberBegin(); it != sobj.MemberEnd(); it++ ) {
		out << "Parameter set " << it->name.GetString() << std::endl;

		char writeBuffer[1024];
		rapidjson::FileWriteStream os(stdout, writeBuffer, sizeof(writeBuffer));
		rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);

		it->value.Accept(writer);
		out << std::endl;
	}
}

template <class Element>
void
CryptoContextHelper<Element>::printAllParmSetNames(std::ostream& out, const std::string& fn)
{
	Serialized sobj;

	if( !getParmsFile(fn, &sobj) ) {
		out << "Unable to read serialization from " << fn << std::endl;
		return;
	}

	Serialized::ConstMemberIterator it = sobj.MemberBegin();
	out << it->name.GetString();

	for( it++; it != sobj.MemberEnd(); it++ ) {
		out << ", " << it->name.GetString();
	}
	out << std::endl;
}

}
