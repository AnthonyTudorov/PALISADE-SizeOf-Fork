
#include "ildcrtparams.h"
#include "utils/serializablehelper.h"

namespace lbcrypto {

ILDCRTParams::ILDCRTParams(usint order, usint depth) {
	m_cyclotomicOrder = order;
	m_parms.resize(depth);

	// FIXME on this starting q
	native64::BigBinaryInteger q("50000");
	native64::BigBinaryInteger temp;
	BigBinaryInteger modulus(BigBinaryInteger::ONE);

	native64::BigBinaryInteger mod, root;

	for (int j = 0; j < depth; j++) {
		lbcrypto::NextQ<native64::BigBinaryInteger>(q, native64::BigBinaryInteger::FIVE, order, native64::BigBinaryInteger::FOUR, native64::BigBinaryInteger::FOUR);
		mod = q;
		root = RootOfUnity<native64::BigBinaryInteger>(order, mod);

		std::shared_ptr<native64::ILParams> p( new native64::ILParams(order, mod, root) );
		m_parms[j] = p;
		modulus = modulus * BigBinaryInteger(mod.ConvertToInt());
	}

	this->m_modulus = modulus;
}

bool
ILDCRTParams::Serialize(Serialized* serObj) const
{
	if( !serObj->IsObject() )
		return false;

	Serialized ser(rapidjson::kObjectType, &serObj->GetAllocator());

	ser.AddMember("Modulus", m_modulus.ToString(), ser.GetAllocator());
	ser.AddMember("Order", std::to_string(m_cyclotomicOrder), ser.GetAllocator());
	SerializeVectorOfPointers<native64::ILParams>("Params", "ILParams", m_parms, &ser);

	serObj->AddMember("ILDCRTParams", ser, serObj->GetAllocator());

	return true;
}

//JSON FACILITY
bool
ILDCRTParams::Deserialize(const Serialized& serObj)
{
	Serialized::ConstMemberIterator rIt = serObj.FindMember("ILDCRTParams");
	if( rIt == serObj.MemberEnd() ) return false;

	const SerialItem& arr = rIt->value;

	Serialized::ConstMemberIterator it = arr.FindMember("Modulus");
	if( it == arr.MemberEnd() ) return false;
	BigBinaryInteger modulus( it->value.GetString() );
	this->m_modulus = modulus;

	it = arr.FindMember("Order");
	if( it == arr.MemberEnd() ) return false;
	this->m_cyclotomicOrder = std::stoi(it->value.GetString());

	return DeserializeVectorOfPointers<native64::ILParams>("Params", "ILParams", it, &this->m_parms);
}


}
