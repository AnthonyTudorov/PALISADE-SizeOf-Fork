/*
 * matrixser.cpp
 *
 *  Created on: Feb 7, 2017
 *      Author: gerardryan
 */

// this is the implementation of matrixes of things that are in pke

#include "palisade.h"
#include "cryptocontext.h"
#include "utils/serializablehelper.h"
#include "rationalciphertext.h"

#include "math/matrix.cpp"
using std::invalid_argument;

namespace lbcrypto {

template class Matrix<RationalCiphertext<ILVector2n>>;

template<>
bool Matrix<RationalCiphertext<ILVector2n>>::Serialize(Serialized* serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "Matrix", serObj->GetAllocator());
	serObj->AddMember("ElementObject", "RationalCiphertext<ILVector2n>", serObj->GetAllocator());
	serObj->AddMember("Rows", std::to_string(rows), serObj->GetAllocator());
	serObj->AddMember("Cols", std::to_string(cols), serObj->GetAllocator());

	int elCount = 0;

	for( size_t r=0; r<rows; r++ ) {
		for( size_t c=0; c<cols; c++ ) {
			Serialized elSer(rapidjson::kObjectType, &serObj->GetAllocator());

			if( (*this)(r,c).Serialize(&elSer) == false )
				return false;

			Serialized fullElSer(rapidjson::kObjectType, &serObj->GetAllocator());

			fullElSer.AddMember("row", std::to_string(r), serObj->GetAllocator());
			fullElSer.AddMember("col", std::to_string(c), serObj->GetAllocator());
			fullElSer.AddMember("entry", elSer.Move(), serObj->GetAllocator());

			SerialItem key( std::to_string(elCount), serObj->GetAllocator() );
			serObj->AddMember(key, fullElSer.Move(), serObj->GetAllocator());

			elCount++;
		}
	}

	return true;
}

template<>
bool Matrix<RationalCiphertext<ILVector2n>>::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Matrix" )
		return false;

	mIter = serObj.FindMember("ElementObject");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "RationalCiphertext<ILVector2n>" )
		return false;

	mIter = serObj.FindMember("Rows");
	if( mIter == serObj.MemberEnd() )
		return false;

	int mrows = std::stoi( mIter->value.GetString() );

	mIter = serObj.FindMember("Cols");
	if( mIter == serObj.MemberEnd() )
		return false;

	int mcols = std::stoi( mIter->value.GetString() );

	auto tempElement = this->allocZero();
	CryptoContext<ILVector2n> cc = tempElement->GetCryptoContext();

	if( bool(cc) == false )
		return false;

	this->SetSize(mrows, mcols);

	for( size_t i=0; i<rows*cols; i++ ) {
		mIter = serObj.FindMember( std::to_string(i) );
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized oneItem(rapidjson::kObjectType);
		SerialItem val( mIter->value, oneItem.GetAllocator() );
		val.Swap(oneItem);

		mIter = oneItem.FindMember("row");
		if( mIter == serObj.MemberEnd() )
			return false;

		int thisRow = std::stoi( mIter->value.GetString() );

		mIter = oneItem.FindMember("col");
		if( mIter == serObj.MemberEnd() )
			return false;

		int thisCol = std::stoi( mIter->value.GetString() );

		mIter = oneItem.FindMember("entry");
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized mEntry(rapidjson::kObjectType);
		SerialItem mVal( mIter->value, mEntry.GetAllocator() );
		mVal.Swap(mEntry);

		RationalCiphertext<ILVector2n> entry(cc);

		if( entry.Deserialize(mEntry) == false )
			return false;

		(*this)(thisRow,thisCol) = std::move(entry);
	}

	return true;
}

template<>
bool Matrix<RationalCiphertext<ILVectorArray2n>>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<RationalCiphertext<ILVectorArray2n>>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<Ciphertext<ILVector2n>>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<Ciphertext<ILVector2n>>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<Ciphertext<ILVectorArray2n>>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<Ciphertext<ILVectorArray2n>>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
Matrix<RationalCiphertext<ILVector2n>>& Matrix<RationalCiphertext<ILVector2n>>::Ones() {
	throw std::logic_error("Cannot fill matrix of ciphertext with 1's");
}

template<>
Matrix<RationalCiphertext<ILVector2n>>& Matrix<RationalCiphertext<ILVector2n>>::Identity() {
	throw std::logic_error("Cannot create identity matrix of ciphertext");
}

template<>
Matrix<RationalCiphertext<ILVector2n>> Matrix<RationalCiphertext<ILVector2n>>::GadgetVector() const {
	throw std::logic_error("Cannot create gadget matrix of ciphertext");
}



}
