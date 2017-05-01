
#include "ildcrtparams.h"
#include "../utils/serializablehelper.h"


namespace lbcrypto {

ILDCRTParams::ILDCRTParams(usint order, usint depth, usint bits) : ElemParams<BigBinaryInteger>(order) {

	if( order == 0 )
		return;
	if( depth == 0 )
		throw std::logic_error("Invalid depth for ILDCRTParams");
	if( bits == 0 )
		throw std::logic_error("Invalid bits for ILDCRTParams");

	m_parms.resize(depth);
	this->ciphertextModulus = BigBinaryInteger::ZERO;

	native64::BigBinaryInteger q = FindPrimeModulus<native64::BigBinaryInteger>(order, bits);

	for(int j = 0; ;) {
		native64::BigBinaryInteger root = RootOfUnity<native64::BigBinaryInteger>(order, q);
		std::shared_ptr<native64::ILParams> p( new native64::ILParams(order, q, root) );
		m_parms[j] = p;

		if( ++j >= depth )
			break;

		lbcrypto::NextQ<native64::BigBinaryInteger>(q, native64::BigBinaryInteger::FIVE, order, native64::BigBinaryInteger::FOUR, native64::BigBinaryInteger::FOUR);
	}

	RecalculateModulus();
}

template<typename IntType>
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

	it = arr.FindMember("Params");

	if( it == arr.MemberEnd() ) {
		return false;
	}

	return DeserializeVectorOfPointers<native64::ILParams>("Params", "ILParams", it, &this->m_parms);
}


}
