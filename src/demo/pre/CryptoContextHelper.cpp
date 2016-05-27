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

	string parmtype;
	string plaintextModulus;
	string ring;
	string modulus;
	string rootOfUnity;
	string relinWindow;
	string stDev;
	string stDevStSt;

	if( !getValueForName(it->value, "parameters", parmtype) ) {
		cerr << "parameters element is missing" << endl;
		return 0;
	}

	if( parmtype == "LTV" ) {
		if( !getValueForName(it->value, "plaintextModulus", plaintextModulus) ||
				!getValueForName(it->value, "ring", ring) ||
				!getValueForName(it->value, "modulus", modulus) ||
				!getValueForName(it->value, "rootOfUnity", rootOfUnity) ||
				!getValueForName(it->value, "relinWindow", relinWindow) ||
				!getValueForName(it->value, "stDev", stDev) ) {
			return 0;
		}

		return CryptoContext::genCryptoContextLTV(stoul(plaintextModulus), stoul(ring),
				modulus, rootOfUnity, stoul(relinWindow), stof(stDev));
	}
	else if( parmtype == "StehleSteinfeld" ) {
		if( !getValueForName(it->value, "plaintextModulus", plaintextModulus) ||
				!getValueForName(it->value, "ring", ring) ||
				!getValueForName(it->value, "modulus", modulus) ||
				!getValueForName(it->value, "rootOfUnity", rootOfUnity) ||
				!getValueForName(it->value, "relinWindow", relinWindow) ||
				!getValueForName(it->value, "stDev", stDev) ||
				!getValueForName(it->value, "stDevStSt", stDevStSt) ) {
			return 0;
		}

		return CryptoContext::genCryptoContextStehleSteinfeld(stoul(plaintextModulus), stoul(ring),
				modulus, rootOfUnity, stoul(relinWindow), stof(stDev), stof(stDevStSt));
	}

	return 0;
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

