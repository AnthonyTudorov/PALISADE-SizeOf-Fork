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

// please note that for things like Ones, etc, there's gotta be a better way...

namespace lbcrypto {

template class Matrix<ILVector2n>;
template class Matrix<BigBinaryInteger>;
template class Matrix<BigBinaryVector>;
template class Matrix<double>;
template class Matrix<int>;

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
	//SerializeVectorOfVector("Matrix", elementName<Element>(), this->data, serObj);

	//std::cout << typeid(Element).name() << std::endl;

	for( size_t r=0; r<rows; r++ ) {
		for( size_t c=0; c<cols; c++ ) {
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

#define ONES_FOR_TYPE(T) \
template<> \
Matrix<T>& Matrix<T>::Ones() { \
    for (size_t row = 0; row < rows; ++row) { \
        for (size_t col = 0; col < cols; ++col) { \
            *data[row][col] = 1; \
        } \
    } \
    return *this; \
}

ONES_FOR_TYPE(int32_t)
ONES_FOR_TYPE(double)
ONES_FOR_TYPE(ILVector2n)
ONES_FOR_TYPE(BigBinaryInteger)
ONES_FOR_TYPE(BigBinaryVector)
ONES_FOR_TYPE(IntPlaintextEncoding)
ONES_FOR_TYPE(Field2n)

#define IDENTITY_FOR_TYPE(T) \
template<> \
Matrix<T>& Matrix<T>::Identity() { \
    for (size_t row = 0; row < rows; ++row) { \
        for (size_t col = 0; col < cols; ++col) { \
            if (row == col) { \
                *data[row][col] = 1; \
            } else { \
                *data[row][col] = 0; \
            } \
        } \
    } \
    return *this; \
}

IDENTITY_FOR_TYPE(int32_t)
IDENTITY_FOR_TYPE(double)
IDENTITY_FOR_TYPE(ILVector2n)
IDENTITY_FOR_TYPE(BigBinaryInteger)
IDENTITY_FOR_TYPE(BigBinaryVector)
IDENTITY_FOR_TYPE(IntPlaintextEncoding)
IDENTITY_FOR_TYPE(Field2n)

#define GADGET_FOR_TYPE(T) \
template<> \
Matrix<T> Matrix<T>::GadgetVector() const { \
    Matrix<T> g(allocZero, rows, cols); \
    auto two = allocZero(); \
    *two = 2; \
    g(0, 0) = 1; \
    for (size_t col = 1; col < cols; ++col) { \
        g(0, col) = g(0, col-1) * *two; \
    } \
    return g; \
}


GADGET_FOR_TYPE(int32_t)
GADGET_FOR_TYPE(double)
GADGET_FOR_TYPE(ILVector2n)
GADGET_FOR_TYPE(BigBinaryInteger)
GADGET_FOR_TYPE(BigBinaryVector)
//GADGET_FOR_TYPE(IntPlaintextEncoding)
GADGET_FOR_TYPE(Field2n)


}

