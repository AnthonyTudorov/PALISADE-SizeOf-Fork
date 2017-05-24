
#include "ildcrtparams.h"
#include "../utils/serializablehelper.h"


namespace lbcrypto {

template<typename IntType>
ILDCRTParams<IntType>::ILDCRTParams(usint order, usint depth, usint bits) : ElemParams<IntType>(order, 0, 0, 0, 0) {

	static native64::BigBinaryInteger FIVE(5);
	static native64::BigBinaryInteger FOUR(5);
	if( order == 0 )
		return;
	if( depth == 0 )
		throw std::logic_error("Invalid depth for ILDCRTParams");
	if( bits == 0 )
		throw std::logic_error("Invalid bits for ILDCRTParams");

	m_parms.resize(depth);
	this->ciphertextModulus = BigBinaryInteger::ZERO;

	native_int::BigBinaryInteger q = FindPrimeModulus<native_int::BigBinaryInteger>(order, bits);

	for(size_t j = 0; ;) {
		native_int::BigBinaryInteger root = RootOfUnity<native_int::BigBinaryInteger>(order, q);
		std::shared_ptr<native_int::ILParams> p( new native_int::ILParams(order, q, root) );
		m_parms[j] = p;

		if( ++j >= depth )
			break;

		lbcrypto::NextQ<native_int::BigBinaryInteger>(q, native_int::BigBinaryInteger::FIVE, order, native_int::BigBinaryInteger::FOUR, native_int::BigBinaryInteger::FOUR);
	}

	RecalculateModulus();
}

template<typename IntType>
bool
ILDCRTParams<IntType>::Serialize(Serialized* serObj) const
{
	if( !serObj->IsObject() )
		return false;

	Serialized ser(rapidjson::kObjectType, &serObj->GetAllocator());

	SerializeVectorOfPointers<native_int::ILParams>("Params", "ILParams", m_parms, &ser);

	serObj->AddMember("ILDCRTParams", ser, serObj->GetAllocator());

	return true;
}

template<typename IntType>
bool
ILDCRTParams<IntType>::Deserialize(const Serialized& serObj)
{
	Serialized::ConstMemberIterator rIt = serObj.FindMember("ILDCRTParams");
	if( rIt == serObj.MemberEnd() ) return false;

	const SerialItem& arr = rIt->value;

	Serialized::ConstMemberIterator it = arr.FindMember("Params");

	if( it == arr.MemberEnd() ) {
		return false;
	}

	if( DeserializeVectorOfPointers<native_int::ILParams>("Params", "ILParams", it, &this->m_parms) == false )
		return false;

	this->cyclotomicOrder = this->m_parms[0]->GetCyclotomicOrder();
	this->ringDimension = this->m_parms[0]->GetRingDimension();
	this->isPowerOfTwo = this->ringDimension == this->cyclotomicOrder / 2;

	RecalculateModulus();
	return true;
}


}
