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

#include "matrix.h"
using std::invalid_argument;

namespace lbcrypto {

template<class Element>
Matrix<Element>::Matrix(alloc_func allocZero, size_t rows, size_t cols): rows(rows), cols(cols), data(), allocZero(allocZero) {
    data.resize(rows);
    for (auto row = data.begin(); row != data.end(); ++row) {
        for (size_t col = 0; col < cols; ++col) {
            row->push_back(allocZero());
        }
    }
}

template<class Element>
Matrix<Element>::Matrix(alloc_func allocZero, size_t rows, size_t cols, alloc_func allocGen): rows(rows), cols(cols), data(), allocZero(allocZero) {
    data.resize(rows);
    for (auto row = data.begin(); row != data.end(); ++row) {
        for (size_t col = 0; col < cols; ++col) {
            row->push_back(allocGen());
        }
    }
}

template<class Element>
Matrix<Element>::Matrix(const Matrix<Element>& other) : data(), rows(other.rows), cols(other.cols), allocZero(other.allocZero) {
    deepCopyData(other.data);
}

template<class Element>
Matrix<Element>& Matrix<Element>::operator=(const Matrix<Element>& other) {
    rows = other.rows;
    cols = other.cols;
    deepCopyData(other.data);
    return *this;
}

template<class Element>
Matrix<Element>& Matrix<Element>::Ones() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            *data[row][col] = 1;
        }
    }
    return *this;
}

template<class Element>
Matrix<Element>& Matrix<Element>::Fill(Element val) {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            *data[row][col] = val;
        }
    }
    return *this;
}

template<class Element>
Matrix<Element>& Matrix<Element>::Identity() {
    for (size_t row = 0; row < rows; ++row) {
        for (size_t col = 0; col < cols; ++col) {
            if (row == col) {
                *data[row][col] = 1;
            } else {
                *data[row][col] = 0;
            }
        }
    }
    return *this;
}

template<class Element>
Matrix<Element> Matrix<Element>::GadgetVector() const {
    Matrix<Element> g(allocZero, rows, cols);
    auto two = allocZero();
    *two = 2;
    g(0, 0) = 1;
    for (size_t col = 1; col < cols; ++col) {
        g(0, col) = g(0, col-1) * *two;
    }
    return g;
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
    #pragma omp parallel for


    for (int32_t row = 0; row < result.rows; ++row) {

	//if result was zero allocated the following should not be needed
	//for (size_t col = 0; col < result.cols; ++col) { 
	//    *result.data[row][col] = 0;
	//}
	for (int32_t i = 0; i < cols; ++i) {
        for (int32_t col = 0; col < result.cols; ++col) {
                *result.data[row][col] += *data[row][i] * *other.data[i][col];
            }
        }
    }
#endif
    return result;
}

template<class Element>
Matrix<Element> Matrix<Element>::ScalarMult(Element const& other) const {
    Matrix<Element> result(*this);
#if 0
for (size_t row = 0; row < result.rows; ++row) {
        for (size_t col = 0; col < result.cols; ++col) {
            *result.data[row][col] = *result.data[row][col] * other;
        }
    }
#else
#pragma omp parallel for
for (int32_t col = 0; col < result.cols; ++col) {
	for (int32_t row = 0; row < result.rows; ++row) {

            *result.data[row][col] = *result.data[row][col] * other;
        }
    }

#endif
    return result;
}


template<class Element>
bool Matrix<Element>::Equal(Matrix<Element> const& other) const {
    if (rows != other.rows || cols != other.cols) {
        return false;
    }
		
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            if (*data[i][j] != *other.data[i][j]) {
                return false;
            }
        }
    }
    return true;
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
Matrix<Element> Matrix<Element>::Add(Matrix<Element> const& other) const {
    if (rows != other.rows || cols != other.cols) {
        throw invalid_argument("Addition operands have incompatible dimensions");
    }
    Matrix<Element> result(*this);
#if 0
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            *result.data[i][j] += *other.data[i][j];
        }
    }
#else
#pragma omp parallel for
for (int32_t j = 0; j < cols; ++j) {
for (int32_t i = 0; i < rows; ++i) {
            *result.data[i][j] += *other.data[i][j];
        }
    }
#endif
    return result;
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
Matrix<Element> Matrix<Element>::Sub(Matrix<Element> const& other) const {
    if (rows != other.rows || cols != other.cols) {
        throw invalid_argument("Subtraction operands have incompatible dimensions");
    }
    Matrix<Element> result(allocZero, rows, other.cols);
#if 0
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            *result.data[i][j] = *data[i][j] - *other.data[i][j];
        }
    }
#else
    #pragma omp parallel for
for (int32_t j = 0; j < cols; ++j) {
	for (int32_t i = 0; i < rows; ++i) {
            *result.data[i][j] = *data[i][j] - *other.data[i][j];
        }
    }
#endif

    return result;
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

    	for (size_t row = 0; row < rows; ++row) {
    		for (size_t col = 0; col < cols; ++col) {
    			data[row][col]->SwitchFormat();
    		}
    	}

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
Matrix<LargeFloat> Cholesky(const Matrix<int32_t> &input) {
    //  http://eprint.iacr.org/2013/297.pdf
    if (input.GetRows() != input.GetCols()) {
        throw invalid_argument("not square");
    }
    size_t rows = input.GetRows();
    Matrix<LargeFloat> result([](){ return make_unique<LargeFloat>(); }, rows, rows);

    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < rows; ++j) {
            result(i,j) = input(i,j);
        }
    }

    for (size_t k = 0; k < rows; ++k) {
        result(k, k) = sqrt(result(k, k));
        //result(k, k) = sqrt(input(k, k));
        for (size_t i = k+1; i < rows; ++i) {
            //result(i, k) = input(i, k) / result(k, k);
            result(i, k) = result(i, k) / result(k, k);
            //  zero upper-right triangle
            result(k, i) = 0;
        }
        for (size_t j = k+1; j < rows; ++j) {
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
Matrix<ILVector2n> SplitInt32IntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const ILParams &params) {
			
	auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	size_t rows = other.GetRows()/n;

    Matrix<ILVector2n> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {
		BigBinaryVector tempBBV(n,params.GetModulus());

        for (size_t i = 0; i < n; ++i) {
			BigBinaryInteger tempBBI;
			uint32_t tempInteger;
			if (other(row*n + i,0) < 0)
			{
				tempInteger = -other(row*n + i,0);
				tempBBI = params.GetModulus() - BigBinaryInteger(tempInteger);
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
Matrix<ILVector2n> SplitInt32AltIntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const ILParams &params) {
			
	auto zero_alloc = ILVector2n::MakeAllocator(params, COEFFICIENT);

	size_t rows = other.GetRows();

    Matrix<ILVector2n> result(zero_alloc, rows, 1);

    for (size_t row = 0; row < rows; ++row) {

		BigBinaryVector tempBBV(n,params.GetModulus());

        for (size_t i = 0; i < n; ++i) {

			BigBinaryInteger tempBBI;
			uint32_t tempInteger;
			if (other(row,i) < 0)
			{
				tempInteger = -other(row,i);
				tempBBI = params.GetModulus() - BigBinaryInteger(tempInteger);
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



template<class Element>
Element* Matrix<Element>::allocate( long long int s ) {
	//printf("Allocating %lld Elements\n",s);

  return (Element*) calloc( s, sizeof(Element) );
}

template<class Element>
void Matrix<Element>::deallocate( Element *A, long long s ) {

  free(A);
}

template<class Element>
void Matrix<Element>::multiplyCAPS( Element *A, Element *B, Element *C, MatDescriptor desc) {

  printf("lda:%d nrec:%d nproc:%d nprocc:%d nprocr:%d nrpoc_summa:%d bs:%d\n", desc.lda,desc.nrec,desc.nproc,desc.nprocc,desc.nprocr,desc.nproc_summa,desc.bs);

  omp_set_num_threads(NUM_THREADS);

  multiplyInternalCAPS( A, B, C, desc, NULL );

}

// nproc is the number of processors that share the matrices, and will be involved in the multiplication
template<class Element>
void Matrix<Element>::multiplyInternalCAPS(Element *A, Element *B, Element *C, MatDescriptor desc,
		Element *work) {
	if (desc.nrec == 0) { // (planned) out of recursion in the data layout, do a regular matrix multiply.  The matrix is now in a 2d block cyclic layout

		// A 2d block cyclic layout with 1 processor still has blocks to deal with
		// run a 1-proc non-strassen
		block_multiplyCAPS(A, B, C, desc, work);

	} else {
		if (pattern == NULL) {

			//COUNTERS setExecutionType(desc.nrec, "DFS");
			strassenDFSCAPS(A, B, C, desc, work);

		} else {
			if (pattern[0] == 'D' || pattern[0] == 'd') {
				//COUNTERS setExecutionType(desc.nrec, "DFS");
				pattern++;
				strassenDFSCAPS(A, B, C, desc, work);
				pattern--;
			}
		}

	}
}

template<class Element>
void Matrix<Element>::addMatricesCAPS( int numEntries, Element *C, Element *A, Element *B ) {
	//COUNTERS increaseAdditions(numEntries);
	//COUNTERS startTimer(TIMER_ADD);
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ )
    C[i] = A[i] + B[i];
  //COUNTERS stopTimer(TIMER_ADD);
}

template<class Element>
void Matrix<Element>::subMatricesCAPS( int numEntries, Element *C, Element *A, Element *B ) {
	//COUNTERS increaseAdditions(numEntries);
	//COUNTERS startTimer(TIMER_ADD);
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ )
    C[i] = A[i] - B[i];
  //COUNTERS stopTimer(TIMER_ADD);
}
// useful to improve cache behavior if there is some overlap.  It is safe for T_i to be the same as S_j* as long as i<j.  That is, operations will happen in the order specified
template<class Element>
void Matrix<Element>::tripleSubMatricesCAPS(int numEntries, Element *T1, Element *S11, Element *S12, Element *T2,
		       Element *S21, Element *S22, Element *T3, Element *S31, Element *S32) {
	//COUNTERS increaseAdditions(3*numEntries);
	//COUNTERS startTimer(TIMER_ADD);
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ) {
      T1[i] = S11[i] - S12[i];
      T2[i] = S21[i] - S22[i];
      T3[i] = S31[i] - S32[i];
  }
  //COUNTERS stopTimer(TIMER_ADD);
}

template<class Element>
void Matrix<Element>::tripleAddMatricesCAPS(int numEntries, Element *T1, Element *S11, Element *S12, Element *T2,
		       Element *S21, Element *S22, Element *T3, Element *S31, Element *S32) {
	//COUNTERS increaseAdditions(3*numEntries);
	//COUNTERS startTimer(TIMER_ADD);
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ) {
      T1[i] = S11[i] + S12[i];
      T2[i] = S21[i] + S22[i];
      T3[i] = S31[i] + S32[i];
  }
  //COUNTERS stopTimer(TIMER_ADD);
}

template<class Element>
void Matrix<Element>::addSubMatricesCAPS(int numEntries, Element *T1, Element *S11, Element *S12, Element *T2,
		       Element *S21, Element *S22 ) {
	//COUNTERS increaseAdditions(2*numEntries);
	//COUNTERS startTimer(TIMER_ADD);
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ) {
      T1[i] = S11[i] + S12[i];
      T2[i] = S21[i] - S22[i];
  }
  //COUNTERS stopTimer(TIMER_ADD);
}


template<class Element>
void Matrix<Element>::strassenDFSCAPS( Element *A, Element *B, Element *C, MatDescriptor desc, Element *workPassThrough ) {
#ifdef SANITY_CHECKS
  verifyDescriptor( desc );
#endif
  MatDescriptor halfDesc = desc;
  halfDesc.lda /= 2;
  halfDesc.nrec -= 1;
#ifdef SANITY_CHECKS
  verifyDescriptor( halfDesc );
#endif

  // submatrices; these are described by halfDesc;
  long long int numEntriesHalf = numEntriesPerProc(halfDesc);
  Element *A11 = A;
  Element *A21 = A+numEntriesHalf;
  Element *A12 = A+2*numEntriesHalf;
  Element *A22 = A+3*numEntriesHalf;
  Element *B11 = B;
  Element *B21 = B+numEntriesHalf;
  Element *B12 = B+2*numEntriesHalf;
  Element *B22 = B+3*numEntriesHalf;
  Element *C11 = C;
  Element *C21 = C+numEntriesHalf;
  Element *C12 = C+2*numEntriesHalf;
  Element *C22 = C+3*numEntriesHalf;


  // six registers.  halfDesc is the descriptor for these
  Element *R1 = C21;
  Element *R2 = allocate( numEntriesHalf );
  Element *R3 = C11;
  Element *R4 = C22;
  Element *R5 = (Element *)allocate( numEntriesHalf );
  Element *R6 = C12;

  Element *S5 = R1;
  Element *S3 = R2;
  Element *S4 = R3;
  tripleSubMatricesCAPS(numEntriesHalf, S5, B22, B12, S3, B12, B11, S4, B22, S3);
  Element *T5 = R4;
  Element *T3 = R6; // was R1
  addSubMatricesCAPS(numEntriesHalf, T3, A21, A22, T5, A11, A21);
  Element *Q5 = R5;
  multiplyInternalCAPS( T5, S5, Q5, halfDesc, workPassThrough);
  Element *Q3 = R4;
  multiplyInternalCAPS( T3, S3, Q3, halfDesc, workPassThrough);
  Element *T4 = R6;
  subMatricesCAPS(numEntriesHalf, T4, T3, A11);
  Element *Q4 = R2;
  multiplyInternalCAPS( T4, S4, Q4, halfDesc, workPassThrough);
  Element *T6 = R6;
  subMatricesCAPS(numEntriesHalf, T6, A12, T4);
  Element *S7 = R3;
  subMatricesCAPS(numEntriesHalf, S7, S4, B21);
  Element *Q7 = R1;
  multiplyInternalCAPS( A22, S7, Q7, halfDesc, workPassThrough);
  Element *Q1 = R3;
  multiplyInternalCAPS( A11, B11, Q1, halfDesc, workPassThrough);
  Element *U1 = R2;
  Element *U2 = R5;
  Element *U3 = R2;
  tripleAddMatricesCAPS(numEntriesHalf, U1, Q1, Q4, U2, U1, Q5, U3, U1, Q3);
  addSubMatricesCAPS(numEntriesHalf, C22, U2, Q3, C21, U2, Q7);
  Element *Q2 = R5;
  multiplyInternalCAPS( A12, B21, Q2, halfDesc, workPassThrough);
  addMatricesCAPS(numEntriesHalf, C11, Q1, Q2);
  Element *Q6 = R5;
  multiplyInternalCAPS(T6, B22, Q6, halfDesc, workPassThrough);
  addMatricesCAPS(numEntriesHalf, C12, U3, Q6);
  deallocate(R5, numEntriesHalf);
  deallocate(R2, numEntriesHalf);

}

template<class Element>
void Matrix<Element>::block_multiplyCAPS( Element *A, Element *B, Element *C, MatDescriptor d, Element *work ) {
  long long lda = d.lda;
  //long long lda3 = lda*lda*lda;
  //COUNTERS increaseAdditions( lda3 );
  //COUNTERS increaseMultiplications( lda3 );

  Element *AA, *BB, *CC;

    AA = A;
    BB = B;
    CC = C;


  // do the multiplication, without requiring CC to be zeroed
    //COUNTERS startTimer(TIMER_MUL);
  square_dgemm_zero( d.lda, AA, BB, CC );
  //COUNTERS stopTimer(TIMER_MUL);



}


}

