#include "ildcrtparams.h"

namespace lbcrypto {

// utility to serialize and deserialize vectors of BBIs
static bool
SerializeBBIVector(const std::string& vectorName, const std::vector<BigBinaryInteger>& inVector, Serialized* serObj)
{
		SerialItem ser(rapidjson::kObjectType);
		ser.AddMember("Typename", "BigBinaryVector", serObj->GetAllocator());
		ser.AddMember("Length", std::to_string(inVector.size()), serObj->GetAllocator());

		Serialized serElements(rapidjson::kObjectType, &serObj->GetAllocator());
		for( int i=0; i<inVector.size(); i++ ) {
			SerialItem key( std::to_string(i), serObj->GetAllocator() );
			SerialItem val( inVector[i].Serialize(), serObj->GetAllocator() );
			serElements.AddMember(key, val, serObj->GetAllocator());
		}

		ser.AddMember("Members", serElements.Move(), serObj->GetAllocator());

		serObj->AddMember(SerialItem(vectorName, serObj->GetAllocator()), ser.Move(), serObj->GetAllocator());
		return true;
	}

bool
ILDCRTParams::Serialize(Serialized* serObj, const std::string fileFlag) const
{
	if( !serObj->IsObject() )
		return false;

	Serialized ser(rapidjson::kObjectType);
	ser.AddMember("Modulus", this->GetModulus().ToString(), serObj->GetAllocator());
	ser.AddMember("Order", std::to_string(this->GetCyclotomicOrder()), serObj->GetAllocator());
	SerializeBBIVector("Moduli", this->GetModuli(), &ser);
	SerializeBBIVector("RootsOfUnity", this->GetRootsOfUnity(), &ser);

	serObj->AddMember("ILDCRTParams", ser.Move(), serObj->GetAllocator());

	return true;
}

//JSON FACILITY
bool
ILDCRTParams::Deserialize(const Serialized& serObj)
{
	//Place holder
	return false;
}


}
