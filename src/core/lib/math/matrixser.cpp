/*
 * @file matrixser.cpp - matrix serializations operations.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "../utils/serializablehelper.h"
#include "../lattice/field2n.h"
#include "matrix.cpp"
#include "matrixstrassen.h"
using std::invalid_argument;

// this is the implementation of matrixes of things that are in core and that need template specializations

// please note that for things like Ones, etc, there's gotta be a better way than these macros...

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
bool Matrix<PackedIntPlaintextEncoding>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<PackedIntPlaintextEncoding>::Deserialize(const Serialized& serObj) {
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

template<>
double Matrix<ILVector2n>::Norm() const {
    double retVal = 0.0;
	double locVal = 0.0;

	//std::cout << " Norm: " << rows << "-" << cols << "-"  << locVal << "-"  << retVal << std::endl;

	for (size_t row = 0; row < rows; ++row) {
		for (size_t col = 0; col < cols; ++col) {
			locVal = data[row][col]->Norm();
			//std::cout << " Norm: " << row << "-" << col << "-"  << locVal << "-"  << retVal << std::endl;
			if (locVal > retVal) {
				retVal = locVal;
			}
		}
	}

    return retVal;
}

#define NORM_FOR_TYPE(T) \
template<> \
double Matrix<T>::Norm() const { \
    throw std::logic_error("Norm not defined for this type"); \
}


NORM_FOR_TYPE(int32_t)
NORM_FOR_TYPE(double)
NORM_FOR_TYPE(BigBinaryInteger)
NORM_FOR_TYPE(BigBinaryVector)
NORM_FOR_TYPE(Field2n)

template<>
void Matrix<ILVector2n>::SetFormat(Format format) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            data[row][col]->SetFormat(format);
        }
    }
}

Matrix<BigBinaryInteger> Rotate(Matrix<ILVector2n> const& inMat) {
    Matrix<ILVector2n> mat(inMat);
    mat.SetFormat(COEFFICIENT);
    size_t n = mat(0,0).GetLength();
    BigBinaryInteger const& modulus = mat(0,0).GetModulus();
    size_t rows = mat.GetRows() * n;
    size_t cols = mat.GetCols() * n;
    Matrix<BigBinaryInteger> result(BigBinaryInteger::Allocator, rows, cols);
    for (size_t row = 0; row < mat.GetRows(); ++row) {
        for (size_t col = 0; col < mat.GetCols(); ++col) {
            for (size_t rotRow = 0; rotRow < n; ++rotRow) {
                for (size_t rotCol = 0; rotCol < n; ++rotCol) {
                    result(row*n + rotRow, col*n + rotCol) =
                        mat(row, col).GetValues().GetValAtIndex(
                            (rotRow - rotCol + n) % n
                            );
                    //  negate (mod q) upper-right triangle to account for
                    //  (mod x^n + 1)
                    if (rotRow < rotCol) {
                        result(row*n + rotRow, col*n + rotCol) = modulus.ModSub(result(row*n + rotRow, col*n + rotCol), modulus);
                    }
                }
            }
        }
    }
    return result;
}

/**
    *  Each element becomes a square matrix with columns of that element's
    *  rotations in coefficient form.
    */
Matrix<BigBinaryVector> RotateVecResult(Matrix<ILVector2n> const& inMat) {
    Matrix<ILVector2n> mat(inMat);
    mat.SetFormat(COEFFICIENT);
    size_t n = mat(0,0).GetLength();
    BigBinaryInteger const& modulus = mat(0,0).GetModulus();
    BigBinaryVector zero(1, modulus);
    size_t rows = mat.GetRows() * n;
    size_t cols = mat.GetCols() * n;
    auto singleElemBinVecAlloc = [=](){ return make_unique<BigBinaryVector>(1, modulus); };
    Matrix<BigBinaryVector> result(singleElemBinVecAlloc, rows, cols);
    for (size_t row = 0; row < mat.GetRows(); ++row) {
        for (size_t col = 0; col < mat.GetCols(); ++col) {
            for (size_t rotRow = 0; rotRow < n; ++rotRow) {
                for (size_t rotCol = 0; rotCol < n; ++rotCol) {
                    BigBinaryVector& elem = result(row*n + rotRow, col*n + rotCol);
                    elem.SetValAtIndex(0,
                        mat(row, col).GetValues().GetValAtIndex(
                            (rotRow - rotCol + n) % n
                            ));
                    //  negate (mod q) upper-right triangle to account for
                    //  (mod x^n + 1)
                    if (rotRow < rotCol) {
                        result(row*n + rotRow, col*n + rotCol) = zero.ModSub(elem);
                    }
                }
            }
        }
    }
    return result;
}

template<>
void Matrix<ILVector2n>::PrintValues() const {
    for (size_t col = 0; col < cols; ++col) {
        for (size_t row = 0; row < rows; ++row) {
            data[row][col]->PrintValues();
            std::cout << " ";
        }
        std::cout << std::endl;
    }
}

template<>
void Matrix<BigBinaryInteger>::PrintValues() const {
    for (size_t col = 0; col < cols; ++col) {
        for (size_t row = 0; row < rows; ++row) {
            data[row][col]->PrintValues();
            std::cout << " ";
        }
        std::cout << std::endl;
    }
}

template<>
void Matrix<BigBinaryVector>::PrintValues() const {
    for (size_t col = 0; col < cols; ++col) {
        for (size_t row = 0; row < rows; ++row) {
            data[row][col]->PrintValues();
            std::cout << " ";
        }
        std::cout << std::endl;
    }
}

template<>
void Matrix<int>::PrintValues() const {
    for (size_t col = 0; col < cols; ++col) {
        for (size_t row = 0; row < rows; ++row) {
            std::cout << *data[row][col];
            std::cout << " ";
        }
        std::cout << std::endl;
    }
}

template<>
void Matrix<ILVector2n>::SwitchFormat() {

	if (rows == 1)
	{
		for (size_t row = 0; row < rows; ++row) {
#pragma omp parallel for
			for (size_t col = 0; col < cols; ++col) {
				data[row][col]->SwitchFormat();
			}
		}
	}
	else
	{
		for (size_t col = 0; col < cols; ++col) {
#pragma omp parallel for
			for (size_t row = 0; row < rows; ++row) {
				data[row][col]->SwitchFormat();
			}
		}
	}
}

// YSP removed the Matrix class because it is not defined for all possible data types
// needs to be checked to make sure input matrix is used in the right places
// the assumption is that covariance matrix does not have large coefficients because it is formed by
// discrete gaussians e and s; this implies int32_t can be used
// This algorithm can be further improved - see the Darmstadt paper section 4.4
Matrix<double> Cholesky(const Matrix<int32_t> &input) {
	//  http://eprint.iacr.org/2013/297.pdf
	if (input.GetRows() != input.GetCols()) {
		throw invalid_argument("not square");
	}
	size_t rows = input.GetRows();
	Matrix<double> result([]() { return make_unique<double>(); }, rows, rows);

	for (size_t i = 0; i < rows; ++i) {
		for (size_t j = 0; j < rows; ++j) {
			result(i, j) = input(i, j);
		}
	}

	for (size_t k = 0; k < rows; ++k) {
		result(k, k) = sqrt(result(k, k));
		//result(k, k) = sqrt(input(k, k));
		for (size_t i = k + 1; i < rows; ++i) {
			//result(i, k) = input(i, k) / result(k, k);
			result(i, k) = result(i, k) / result(k, k);
			//  zero upper-right triangle
			result(k, i) = 0;
		}
		for (size_t j = k + 1; j < rows; ++j) {
			for (size_t i = j; i < rows; ++i) {
				if (result(i, k) != 0 && result(j, k) != 0) {
					result(i, j) = result(i, j) - result(i, k) * result(j, k);
					//result(i, j) = input(i, j) - result(i, k) * result(j, k);

				}
			}
		}
	}
	return result;
}

void Cholesky(const Matrix<int32_t> &input, Matrix<double> &result) {
	//  http://eprint.iacr.org/2013/297.pdf
	if (input.GetRows() != input.GetCols()) {
		throw invalid_argument("not square");
	}
	size_t rows = input.GetRows();
//	Matrix<LargeFloat> result([]() { return make_unique<LargeFloat>(); }, rows, rows);

	for (size_t i = 0; i < rows; ++i) {
		for (size_t j = 0; j < rows; ++j) {
			result(i, j) = input(i, j);
		}
	}

	for (size_t k = 0; k < rows; ++k) {

		result(k, k) = sqrt(input(k, k));

		for (size_t i = k + 1; i < rows; ++i) {
			//result(i, k) = input(i, k) / result(k, k);
			result(i, k) = result(i, k) / result(k, k);
			//  zero upper-right triangle
			result(k, i) = 0;
		}
		for (size_t j = k + 1; j < rows; ++j) {
			for (size_t i = j; i < rows; ++i) {
				if (result(i, k) != 0 && result(j, k) != 0) {
					result(i, j) = result(i, j) - result(i, k) * result(j, k);
					//result(i, j) = input(i, j) - result(i, k) * result(j, k);

				}
			}
		}
	}
}


//  Convert from Z_q to [-q/2, q/2]
Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryInteger> &input, const BigBinaryInteger& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    BigBinaryInteger negativeThreshold(modulus / BigBinaryInteger::TWO);
    Matrix<int32_t> result([](){ return make_unique<int32_t>(); }, rows, cols);
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            if (input(i,j) > negativeThreshold) {
                result(i,j) = -1 *(modulus - input(i,j)).ConvertToInt();
            } else {
                result(i,j) = input(i,j).ConvertToInt();
            }
        }
    }
    return result;
}

Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryVector> &input, const BigBinaryInteger& modulus) {
    size_t rows = input.GetRows();
    size_t cols = input.GetCols();
    BigBinaryInteger negativeThreshold(modulus / BigBinaryInteger::TWO);
    Matrix<int32_t> result([](){ return make_unique<int32_t>(); }, rows, cols);
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            const BigBinaryInteger& elem = input(i,j).GetValAtIndex(0);
            if (elem > negativeThreshold) {
                result(i,j) = -1*(modulus - elem).ConvertToInt();
            } else {
                result(i,j) = elem.ConvertToInt();
            }
        }
    }
    return result;
}

//  split a vector of int32_t into a vector of ring elements with ring dimension n
Matrix<ILVector2n> SplitInt32IntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const shared_ptr<ILParams> params) {

	auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	size_t rows = other.GetRows()/n;

    Matrix<ILVector2n> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {
		BigBinaryVector tempBBV(n,params->GetModulus());

        for (size_t i = 0; i < n; ++i) {
			BigBinaryInteger tempBBI;
			uint32_t tempInteger;
			if (other(row*n + i,0) < 0)
			{
				tempInteger = -other(row*n + i,0);
				tempBBI = params->GetModulus() - BigBinaryInteger(tempInteger);
			}
			else
			{
				tempInteger = other(row*n + i,0);
				tempBBI = BigBinaryInteger(tempInteger);
			}
            tempBBV.SetValAtIndex(i,tempBBI);
        }

		result(row,0).SetValues(tempBBV,COEFFICIENT);
    }

    return result;
}

//  split a vector of BBI into a vector of ring elements with ring dimension n
Matrix<ILVector2n> SplitInt32AltIntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const shared_ptr<ILParams> params) {

	auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	size_t rows = other.GetRows();

    Matrix<ILVector2n> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {

		BigBinaryVector tempBBV(n,params->GetModulus());

        for (size_t i = 0; i < n; ++i) {

			BigBinaryInteger tempBBI;
			uint32_t tempInteger;
			if (other(row,i) < 0)
			{
				tempInteger = -other(row,i);
				tempBBI = params->GetModulus() - BigBinaryInteger(tempInteger);
			}
			else
			{
				tempInteger = other(row,i);
				tempBBI = BigBinaryInteger(tempInteger);
			}

			tempBBV.SetValAtIndex(i,tempBBI);
        }

		result(row,0).SetValues(tempBBV,COEFFICIENT);
    }

    return result;
}


}

