#include "ildcrtparams.h"

namespace lbcrypto {

// utility to serialize and deserialize vectors of BBIs
static bool
SerializeBBIVector(const std::string& vectorName, const std::vector<BigBinaryInteger>& inVector, Serialized* serObj)
{
	Serialized ser(rapidjson::kObjectType, &serObj->GetAllocator());
	ser.AddMember("Typename", "BigBinaryVector", serObj->GetAllocator());
	ser.AddMember("Length", std::to_string(inVector.size()), serObj->GetAllocator());

	Serialized serElements(rapidjson::kObjectType, &serObj->GetAllocator());
	for( int i=0; i<inVector.size(); i++ ) {
		SerialItem key( std::to_string(i), serObj->GetAllocator() );
		SerialItem val( inVector[i].Serialize(), serObj->GetAllocator() );
		serElements.AddMember(key, val, serObj->GetAllocator());
	}

	ser.AddMember("Members", serElements, serObj->GetAllocator());

	serObj->AddMember(SerialItem(vectorName, serObj->GetAllocator()), ser, serObj->GetAllocator());
	return true;
}

static bool
DeSerializeBBIVector(const std::string& vectorName, const Serialized& serObj, std::vector<BigBinaryInteger>* inVector)
{
	Serialized::ConstMemberIterator rIt = serObj.FindMember(vectorName);
	if( rIt == serObj.MemberEnd() ) return false;

	const SerialItem& arr = rIt->value;

	Serialized::ConstMemberIterator lIt = arr.FindMember("Length");
	if( lIt == arr.MemberEnd() ) return false;

	int len = std::stoi(lIt->value.GetString());
	inVector->clear();
	inVector->resize(len);

	Serialized::ConstMemberIterator mIt = arr.FindMember("Members");
	if( mIt == arr.MemberEnd() ) return false;

	const SerialItem& members = mIt->value;

	for( int i=0; i < len; i++ ) {
		Serialized::ConstMemberIterator eIt = members.FindMember( std::to_string(i) );
		if( eIt == members.MemberEnd() ) return false;

		BigBinaryInteger vectorElem;
		vectorElem.Deserialize(eIt->value.GetString());
		inVector->at(i) = vectorElem;
	}

	return true;
}


bool
ILDCRTParams::Serialize(Serialized* serObj, const std::string fileFlag) const
{
	if( !serObj->IsObject() )
		return false;

	Serialized ser(rapidjson::kObjectType, &serObj->GetAllocator());
	ser.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());
	ser.AddMember("Order", std::to_string(this->GetCyclotomicOrder()), serObj->GetAllocator());
	SerializeBBIVector("Moduli", this->GetModuli(), &ser);
	SerializeBBIVector("RootsOfUnity", this->GetRootsOfUnity(), &ser);

	serObj->AddMember("ILDCRTParams", ser, serObj->GetAllocator());

	return true;
}

//JSON FACILITY
bool
ILDCRTParams::Deserialize(const Serialized& serObj)
{
	//Place holder
	return false;

	DeSerializeBBIVector("Moduli", serObj, &this->m_moduli);
	DeSerializeBBIVector("RootsOfUnity", serObj, &this->m_rootsOfUnity);

}


}
