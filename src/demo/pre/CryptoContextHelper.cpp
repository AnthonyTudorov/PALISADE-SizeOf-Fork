/*
 * CryptoContextHelper.cpp
 *
 *  Created on: May 27, 2016
 *      Author: gwryan
 */

#include "CryptoContext.h"
#include "CryptoContextHelper.h"
#include "rapidjson/filewritestream.h"

using namespace std;
using namespace lbcrypto;

static bool
getParmsFile(const string& fn, Serialized* obj)
{
	return SerializableHelper::ReadSerializationFromFile(fn, obj);
}

static bool
getValueForName(const SerialItem& allvals, const char *key, string& value)
{
	Serialized::ConstMemberIterator it;
	if( (it = allvals.FindMember(key)) == allvals.MemberEnd() ) {
		cerr << key << " element is missing" << endl;
		return false;
	}

	value = it->value.GetString();
	return true;
}

static CryptoContext *
buildContextFromSerialized(const SerialItem& s)
{
	string parmtype;
	string plaintextModulus;
	string ring;
	string modulus;
	string rootOfUnity;
	string relinWindow;
	string stDev;
	string stDevStSt;

	if( !getValueForName(s, "parameters", parmtype) ) {
		cerr << "parameters element is missing" << endl;
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

		return CryptoContext::genCryptoContextLTV(stoul(plaintextModulus), stoul(ring),
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

		return CryptoContext::genCryptoContextStehleSteinfeld(stoul(plaintextModulus), stoul(ring),
				modulus, rootOfUnity, stoul(relinWindow), stof(stDev), stof(stDevStSt));
	}

	return 0;
}

CryptoContext *
getNewContext(const string& parmSetJson)
{
	// convert string to a map
	Serialized sObj;
	sObj.Parse( parmSetJson.c_str() );
	if( sObj.HasParseError() )
		return 0;
	return buildContextFromSerialized(sObj);
}

CryptoContext *
getNewContext(const string& parmfile, const string& parmset)
{
	Serialized sobj;

	if( !getParmsFile(parmfile, &sobj) ) {
		cerr << "Unable to read serialization from " << parmfile << endl;
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
	return buildContextFromSerialized(cObj);
}

void
printAllParmSets(ostream& out, const std::string& fn)
{
	Serialized sobj;

	if( !getParmsFile(fn, &sobj) ) {
		out << "Unable to read serialization from " << fn << endl;
		return;
	}

	for( Serialized::ConstMemberIterator it = sobj.MemberBegin(); it != sobj.MemberEnd(); it++ ) {
		out << "Parameter set " << it->name.GetString() << endl;

		char writeBuffer[1024];
		rapidjson::FileWriteStream os(stdout, writeBuffer, sizeof(writeBuffer));
		rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);

		it->value.Accept(writer);
		out << endl;
	}
}

void
printAllParmSetNames(ostream& out, const std::string& fn)
{
	Serialized sobj;

	if( !getParmsFile(fn, &sobj) ) {
		out << "Unable to read serialization from " << fn << endl;
		return;
	}

	Serialized::ConstMemberIterator it = sobj.MemberBegin();
	out << it->name.GetString();

	for( it++; it != sobj.MemberEnd(); it++ ) {
		out << ", " << it->name.GetString();
	}
	out << endl;
}

