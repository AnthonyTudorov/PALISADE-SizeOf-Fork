/*
PALISADE PROJECT
Version:
v00.01
Last Edited:
5/11/2016 5:37AM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Dr. Dave Cousins, dave@bbn.com
Kevin King, kcking@mit.edu
Description:
This code provide a templated matrix implementation

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "../utils/serializablehelper.h"
//#include "rationalciphertext.h"
#include "matrix.h"

using std::invalid_argument;

namespace lbcrypto {


template<class Element>
Matrix<Element>::Matrix(alloc_func allocZero, size_t rows, size_t cols, alloc_func allocGen): data(), rows(rows), cols(cols), allocZero(allocZero) {
    data.resize(rows);
    for (auto row = data.begin(); row != data.end(); ++row) {
        for (size_t col = 0; col < cols; ++col) {
            row->push_back(allocGen());
        }
    }
}

template<class Element>
Matrix<Element>& Matrix<Element>::operator=(const Matrix<Element>& other) {
    rows = other.rows;
    cols = other.cols;
    deepCopyData(other.data);
    return *this;
}

template<class Element>
Matrix<Element>& Matrix<Element>::Fill(const Element &val) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            *data[row][col] = val;
        }
    }
    return *this;
}

template<class Element>
double Matrix<Element>::Norm() const {
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

template<class Element>
Matrix<Element> Matrix<Element>::Mult(Matrix<Element> const& other) const {
	//NUM_THREADS = omp_get_max_threads();

    if (cols != other.rows) {
        throw invalid_argument("incompatible matrix multiplication");
    }
    Matrix<Element> result(allocZero, rows, other.cols);
#if 0
    for (size_t row = 0; row < result.rows; ++row) {
        for (size_t col = 0; col < result.cols; ++col) {
			*result.data[row][col] = 0;
            for (size_t i = 0; i < cols; ++i) {
                *result.data[row][col] += *data[row][i] * *other.data[i][col];
            }
        }
    }
#else
    if (rows  == 1) {
        #pragma omp parallel for
        for (size_t col = 0; col < result.cols; ++col) {
		for (size_t i = 0; i < cols; ++i) {
		        *result.data[0][col] += *data[0][i] * *other.data[i][col];
		    }
        }
    }
    else
    {
	    #pragma omp parallel for
	    for (size_t row = 0; row < result.rows; ++row) {
		for (size_t i = 0; i < cols; ++i) {
		for (size_t col = 0; col < result.cols; ++col) {
		        *result.data[row][col] += *data[row][i] * *other.data[i][col];
		    }
		}
	    }
    }
#endif
    return result;
}

template<class Element>
void Matrix<Element>::SetFormat(Format format) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            data[row][col]->SetFormat(format);
        }
    }
}

template<class Element>
Matrix<Element>& Matrix<Element>::operator+=(Matrix<Element> const& other) {
    if (rows != other.rows || cols != other.cols) {
        throw invalid_argument("Addition operands have incompatible dimensions");
    }
#if 0
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            data[i][j] += *other.data[i][j];
        }
    }
#else
    #pragma omp parallel for
for (size_t j = 0; j < cols; ++j) {
	for (size_t i = 0; i < rows; ++i) {
            data[i][j] += *other.data[i][j];
        }
    }
#endif
    return *this;
}

template<class Element>
inline Matrix<Element>& Matrix<Element>::operator-=(Matrix<Element> const& other) {
    if (rows != other.rows || cols != other.cols) {
        throw invalid_argument("Subtraction operands have incompatible dimensions");
    }
#if 0
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            *data[i][j] -= *other.data[i][j];
        }
    }
#else
    #pragma omp parallel for
    for (size_t j = 0; j < cols; ++j) {
        for (size_t i = 0; i < rows; ++i) {
            *data[i][j] -= *other.data[i][j];
        }
    }
#endif
    return *this;
}

template<class Element>
Matrix<Element> Matrix<Element>::Transpose() const {
    Matrix<Element> result(allocZero, cols, rows);
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            result(col, row) = (*this)(row, col);
        }
    }
    return result;
}

// YSP The signature of this method needs to be changed in the future
// Laplace's formula is used to find the determinant
// Complexity is O(d!), where d is the dimension
// The determinant of a matrix is expressed in terms of its minors
// recursive implementation
// There are O(d^3) decomposition algorithms that can be implemented to support larger dimensions.
// Examples include the LU decomposition, the QR decomposition or 
// the Cholesky decomposition(for positive definite matrices).
template<class Element>
void Matrix<Element>::Determinant(Element *determinant) const {
	if (rows != cols) 
		throw invalid_argument("Supported only for square matrix");
	//auto determinant = *allocZero();
	if (rows < 1)
		throw invalid_argument("Dimension should be at least one");
	else if (rows == 1)
		*determinant = *data[0][0];
	else if (rows == 2)
		*determinant = *data[0][0] * (*data[1][1]) - *data[1][0] * (*data[0][1]);
	else
	{
		size_t j1, j2;
		size_t n = rows;

		Matrix<Element> result(allocZero, rows - 1, cols - 1);

		// for each column in sub-matrix
		for (j1 = 0; j1 < n; j1++) {

			// build sub-matrix with minor elements excluded
			for (size_t i = 1; i < n; i++) {
				j2 = 0;               // start at first sum-matrix column position
				// loop to copy source matrix less one column
				for (size_t j = 0; j < n; j++) {
					if (j == j1) continue; // don't copy the minor column element

					*result.data[i-1][j2] = *data[i][j];  // copy source element into new sub-matrix
											 // i-1 because new sub-matrix is one row
											 // (and column) smaller with excluded minors
					j2++;                  // move to next sub-matrix column position
				}
			}

			auto tempDeterminant = *allocZero();
			result.Determinant(&tempDeterminant);

			if (j1 % 2 == 0)
				*determinant = *determinant + (*data[0][j1]) * tempDeterminant;
			else
				*determinant = *determinant - (*data[0][j1]) * tempDeterminant;

			//if (j1 % 2 == 0)
			//	determinant = determinant + (*data[0][j1]) * result.Determinant();
			//else
			//	determinant = determinant - (*data[0][j1]) * result.Determinant();

		}
	}
	//return determinant;
	return;
}

// The cofactor matrix is the matrix of determinants of the minors A_{ij} multiplied by -1^{i+j}
// The determinant subroutine is used
template<class Element>
Matrix<Element> Matrix<Element>::CofactorMatrix() const {
	
	if (rows != cols)
		throw invalid_argument("Supported only for square matrix");

	size_t ii, jj, iNew, jNew;

	size_t n = rows;

	Matrix<Element> result(allocZero, rows, cols);

	for (size_t j = 0; j<n; j++) {

		for (size_t i = 0; i<n; i++) {

			Matrix<Element> c(allocZero, rows - 1, cols - 1);

			/* Form the adjoint a_ij */
			iNew = 0;
			for (ii = 0; ii<n; ii++) {
				if (ii == i)
					continue;
				jNew = 0;
				for (jj = 0; jj<n; jj++) {
					if (jj == j)
						continue;
					*c.data[iNew][jNew] = *data[ii][jj];
					jNew++;
				}
				iNew++;
			}

			/* Calculate the determinant */
			auto determinant = *allocZero();
			c.Determinant(&determinant);
			//auto determinant = c.Determinant();

			/* Fill in the elements of the cofactor */
			if ((i + j) % 2 == 0)
				*result.data[i][j] = determinant;
			else
				*result.data[i][j] = -determinant;
		}
	}

	return result;

}

//  add rows to bottom of the matrix
template<class Element>
Matrix<Element>& Matrix<Element>::VStack(Matrix<Element> const& other) {
    if (cols != other.cols) {
        throw invalid_argument("VStack rows not equal size");
    }
    for (size_t row = 0; row < other.rows; ++row) {
        vector<unique_ptr<Element>> rowElems;
        for (auto elem = other.data[row].begin(); elem != other.data[row].end(); ++elem) {
            rowElems.push_back(make_unique<Element>(**elem));
        }
        data.push_back(std::move(rowElems));
    }
    rows += other.rows;
    return *this;
}

//  add cols to right of the matrix
template<class Element>
inline Matrix<Element>& Matrix<Element>::HStack(Matrix<Element> const& other) {
    if (rows != other.rows) {
        throw invalid_argument("HStack cols not equal size");
    }
    for (size_t row = 0; row < rows; ++row) {
        vector<unique_ptr<Element>> rowElems;
        for (auto elem = other.data[row].begin(); elem != other.data[row].end(); ++elem) {
            rowElems.push_back(make_unique<Element>(**elem));
        }
        MoveAppend(data[row], rowElems);
    }
    cols += other.cols;
    return *this;
}

template<class Element>
void Matrix<Element>::PrintValues() const {
    for (size_t col = 0; col < cols; ++col) {
        for (size_t row = 0; row < rows; ++row) {
            data[row][col]->PrintValues();
            std::cout << " ";
        }
        std::cout << std::endl;
    }
}

template<class Element>
void Matrix<Element>::SwitchFormat() {


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

/*
    	for (size_t row = 0; row < rows; ++row) {
	#pragma omp parallel for
    		for (size_t col = 0; col < cols; ++col) {
    			data[row][col]->SwitchFormat();
    		}
    	}
*/

}


template<class Element>
void Matrix<Element>::deepCopyData(data_t const& src) {
    data.clear();
    data.resize(src.size());
    for (size_t row = 0; row < src.size(); ++row) {
        for (auto elem = src[row].begin(); elem != src[row].end(); ++elem) {
            data[row].push_back(make_unique<Element>(**elem));
        }
    }
}

inline Matrix<BigBinaryInteger> Rotate(Matrix<ILVector2n> const& inMat) {
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

template<class Element>
inline std::ostream& operator<<(std::ostream& os, const Matrix<Element>& m){
    os << "[ ";
    for (size_t row = 0; row < m.GetRows(); ++row) {
        os << "[ ";
        for (size_t col = 0; col < m.GetCols(); ++col) {
            os << *m.GetData()[row][col] << " ";
        }
        os << "]\n";
    }
    os << " ]\n";
    return os;
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

#ifdef OUT
/**
* Serialize the object into a Serialized
* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
* @return true if successfully serialized
*/
template<class Element>
bool Matrix<Element>::Serialize(Serialized* serObj) const {
	serObj->SetObject();
std::cout << "SERIALIZING " << rows << ":" << cols << std::endl;
std::cout << data.size() << std::endl;
std::cout << data[0].size() << std::endl;
	//SerializeVectorOfVector("Matrix", elementName<Element>(), this->data, serObj);

	std::cout << typeid(Element).name() << std::endl;

	for( int r=0; r<rows; r++ ) {
		for( int c=0; c<cols; c++ ) {
			data[r][c]->Serialize(serObj);
		}
	}

	return true;
}

/**
* Populate the object from the deserialization of the Serialized
* @param serObj contains the serialized object
* @return true on success
*/
template<class Element>
bool Matrix<Element>::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("Matrix");
	if( mIter == serObj.MemberEnd() )
		return false;

	//return DeserializeVectorOfVector<Element>("Matrix", elementName<Element>(), mIter, &this->data);
	return true;
}
#endif

/*
 * Multiply the matrix by a vector of 1's, which is the same as adding all the
 * elements in the row together.
 * Return a vector that is a rows x 1 matrix.
 */
template<class Element>
Matrix<Element> Matrix<Element>::MultByUnityVector() const {
	Matrix<Element> result(allocZero, rows, 1);

#pragma omp parallel for
	for (size_t row = 0; row < result.rows; ++row) {
		for (size_t col= 0; col<cols; ++col){
				*result.data[row][0] += *data[row][col];
		}
	}

	return result;
}

/*
 * Multiply the matrix by a vector of random 1's and 0's, which is the same as adding select
 * elements in each row together.
 * Return a vector that is a rows x 1 matrix.
 */
template<class Element>
Matrix<Element> Matrix<Element>::MultByRandomVector(std::vector<int> ranvec) const {
	Matrix<Element> result(allocZero, rows, 1);

#pragma omp parallel for
	for (size_t row = 0; row < result.rows; ++row) {
		for (size_t col= 0; col<cols; ++col){
			if (ranvec[col] == 1)
				*result.data[row][0] += *data[row][col];
		}
	}
	return result;
}


}

