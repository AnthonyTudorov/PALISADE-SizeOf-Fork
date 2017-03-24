/*
 * matrixser.cpp
 *
 *  Created on: Feb 7, 2017
 *      Author: gerardryan
 */

#include "../utils/serializablehelper.h"
#include "../lattice/field2n.h"
#include "matrix.h"
#include "matrixstrassen.h"
using std::invalid_argument;

// this is the implementation of matrixes of things that are in core

namespace lbcrypto {

template<>
bool Matrix<int32_t>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<int32_t>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<double>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<double>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<BigBinaryInteger>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<BigBinaryInteger>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<BigBinaryVector>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<BigBinaryVector>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<ILVector2n>::Serialize(Serialized* serObj) const {
	serObj->SetObject();
std::cout << "SERIALIZING " << rows << ":" << cols << std::endl;
std::cout << data.size() << std::endl;
std::cout << data[0].size() << std::endl;
	//SerializeVectorOfVector("Matrix", elementName<Element>(), this->data, serObj);

	//std::cout << typeid(Element).name() << std::endl;

	for( int r=0; r<rows; r++ ) {
		for( int c=0; c<cols; c++ ) {
			data[r][c]->Serialize(serObj);
		}
	}

	return true;
}

template<>
bool Matrix<ILVector2n>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool MatrixStrassen<ILVector2n>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool MatrixStrassen<ILVector2n>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<IntPlaintextEncoding>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<IntPlaintextEncoding>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<Field2n>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<Field2n>::Deserialize(const Serialized& serObj) {
	return false;
}

}
