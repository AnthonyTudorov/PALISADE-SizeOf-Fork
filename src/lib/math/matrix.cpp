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
  //std::cout<<"in Ones"<<std::endl;
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
  //std::cout<<"in Identity"<<std::endl;
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
	omp_set_num_threads(NUM_THREADS);
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
void Matrix<Element>::LinearizeDataCAPS() const{
    lineardata.clear();

    for (size_t row = 0; row < data.size(); ++row) {
        for (auto elem = data[row].begin(); elem != data[row].end(); ++elem) {
            //lineardata.push_back((make_unique<Element>(**elem)));
        	unique_ptr<Element>* elemptr = &(*elem);

            lineardata.push_back(elemptr);
        }
    }
}

template<class Element>
void Matrix<Element>::UnlinearizeDataCAPS() const{
    	int datasize = data.size();
    	int lineardatasize = lineardata.size();
        //printf("data.size() = %d\n",datasize);
        //data.clear();
        //data.resize(datasize);

        //printf("lineardata.size() = %d\n",lineardatasize);

    int row = 0;
    int counter = 0;
    		data[row].clear();
    		data[row].reserve(datasize);
            for (auto elem = lineardata.begin(); elem != lineardata.end(); ++elem) {
            	//std::cout<<"counter = counter "<<" row = "<<row<<std::endl;
            	//std::cout<<"Elem "<<counter<<" is "<<(***elem)<<std::endl;
                //data[row].push_back(make_unique<Element>(**elem));
            	data[row].push_back(make_unique<Element>(***elem));
                //printf("data[%d].size() is now %d\n",row,data[row].size());
                counter++;
                if (counter % rows == 0){
                //if (counter % datasize == 0){
                	row++;
                	if (row < rows){
                		data[row].clear();
                		data[row].reserve(datasize);
                	}

                }

            }
	//int datasize = data.size();
	//int lineardatasize = lineardata.size();
    //printf("data.size() = %d\n",datasize);
    //data.clear();
    //data.resize(datasize);
    //printf("lineardata.size() = %d\n",lineardatasize);

//int row = 0;
//int counter = 0;
        //for (auto elem = lineardata.begin(); elem != lineardata.end(); ++elem) {
        	//printf("counter = %d row = %d\n",counter,row);
            //data[row].push_back(make_unique<Element>(**elem));
            //counter++;
            //if (counter % datasize == 0){
            	//row++;

            //}

        //}


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



template<class Element>
unique_ptr<Element> ** Matrix<Element>::allocate( long long int s ) {
	//printf("Allocating %lld Elements\n",s);

  return (unique_ptr<Element> **) calloc( s, sizeof(unique_ptr<Element> **) );
}

template<class Element>
void Matrix<Element>::deallocate( unique_ptr<Element> **A, long long s ) {

  free(A);
}

template<class Element>
void Matrix<Element>::PrintLinearDataCAPS(unique_ptr<Element> **elem) const{

	//printf("elem = %p  **elem = %f\n",elem, **elem);
}

template<class Element>
Matrix<Element> Matrix<Element>::MultiplyStrassen(const Matrix<Element>& other,int leafsize) const{
	omp_set_num_threads(NUM_THREADS);
	//std::cout <<"In MultiplyStrassen, this rows = "<<rows << " this cols = "<<cols<<std::endl;
	//std::cout <<"In MultiplyStrassen, other rows = "<<other.rows << " other cols = "<<other.cols<<std::endl;
    Matrix<Element> result(allocZero, rows, other.cols);
    this->leafsize = leafsize;
    strassen(this->data,other.data,result.data,rows);


    return result;
}


template<class Element>
Matrix<Element> Matrix<Element>::MultiplyCAPS(Matrix<Element> const& other,int nrec) const{
	int len = rows*rows;
	desc.lda = rows;
	desc.nrec = nrec;
	desc.bs = 1;
	desc.nproc = 1;
	desc.nproc_summa = 1;
	desc.nprocc = 1;
	desc.nprocr = 1;

	omp_set_num_threads(NUM_THREADS);

	//std::cout<<"In MultiplyCAPS"<<std::endl;
    Matrix<Element> result(allocZero, rows, other.cols);


    this->LinearizeDataCAPS();
    other.LinearizeDataCAPS();
    result.LinearizeDataCAPS();
    //printf("Initial result data:\n");
//    for (int i = 0; i < rows*other.cols;i++){
//    	printf("**result.lineardata[%d] = %f\n",i,(double)(**result.lineardata[i]));
//    }

//printf("&lineardata = %p\n",&lineardata);
//PrintLinearDataCAPS(&lineardata[0]);

//for (int32_t row = 0; row < len; ++row) {
//	printf("&(lineardata[%d]) = %p    **(lineardata[%d]) = %f\n",row,&(lineardata[row]),row,**(lineardata[row]));
//	printf("&(other.lineardata[%d]) = %p    **(other.lineardata[%d]) = %f\n",row,&(other.lineardata[row]),row,**(other.lineardata[row]));
//}

//	for (int32_t row = 0; row < rows; ++row) {
//
//		for (int32_t col = 0; col < cols; ++col) {
//			//printf(" *(data[%d][%d]) = %f\n",row,col,*(data[row][col]));data[%d][%d] = %p row,col,data[row][col],
//			printf("&(data[%d][%d]) = %p    *(data[%d][%d]) = %f\n", row, col,
//					&(data[row][col]), row, col, *(data[row][col]));
//
//		}
//	}

lineardata_t thisdata;
lineardata_t otherdata;
lineardata_t resultdata;

for (size_t elem = 0; elem < len; ++elem) {
    resultdata.push_back(new (unique_ptr<Element>));
}


thisdata.resize(len);
otherdata.resize(len);

//std::cout<<"Before distribution, lineardata is :"<<std::endl;
//for (int i = 0; i < lineardata.size();i++){
//	std::cout<<**lineardata[i]<<" ";
//}
//std::cout<<std::endl<<"thisdata is :"<<std::endl;
//for (int i = 0; i < thisdata.size();i++){
//	std::cout<<**thisdata[i]<<" ";
//}
//std::cout<<std::endl;
distributeFrom1ProcCAPS( desc,&thisdata[0], &lineardata[0]);
//std::cout<<"After distribution, lineardata is :"<<std::endl;
//for (int i = 0; i < lineardata.size();i++){
//	std::cout<<**lineardata[i]<<" ";
//}
//std::cout<<std::endl<<"thisdata is :"<<std::endl;
//for (int i = 0; i < thisdata.size();i++){
//	std::cout<<**thisdata[i]<<" ";
//}
//std::cout<<std::endl;
distributeFrom1ProcCAPS( desc, &otherdata[0], &(other.lineardata[0]));
//std::cout<<"After distribution, other.lineardata is :"<<std::endl;
//for (int i = 0; i < other.lineardata.size();i++){
//	std::cout<<**(other.lineardata[i])<<" ";
//}
//std::cout<<std::endl<<"otherdata is :"<<std::endl;
//for (int i = 0; i < otherdata.size();i++){
//	std::cout<<**otherdata[i]<<" ";
//}
//std::cout<<std::endl;
//multiplyInternalCAPS(&lineardata[0], &(other.lineardata[0]), &(result.lineardata[0]), desc, 0);

//std::cout<<std::endl<<"resultdata before multiplyInternal is :"<<std::endl;
//for (int i = 0; i < resultdata.size();i++){
//	std::cout<<**resultdata[i]<<" ";
//}
//std::cout<<std::endl;
multiplyInternalCAPS(&otherdata[0], &thisdata[0], &resultdata[0] /*,&(result.lineardata[0])*/, desc, 0);//&(result.lineardata[0])
//std::cout<<std::endl<<"resultdata after multiplyInternal is :"<<std::endl;
//for (int i = 0; i < resultdata.size();i++){
//	std::cout<<**resultdata[i]<<" ";
//}
//std::cout<<std::endl;

//for (int32_t row = 0; row < len; ++row) {
//
//	printf("&(result.lineardata[%d]) = %p    *(result.lineardata[%d]) = %f\n",row,&(result.lineardata[row]),row,*(result.lineardata[row]));
//}
//std::cout<<"Done with multiplyInternalCAPS"<<std::endl;
collectTo1ProcCAPS( desc, &(result.lineardata[0]), &resultdata[0] );
//std::cout<<"After collection, resultdata is :"<<std::endl;
//for (int i = 0; i < resultdata.size();i++){
//	std::cout<<*(resultdata[i])<<" ";
//}
//std::cout<<std::endl<<"result.lineardata is :"<<std::endl;
//for (int i = 0; i < result.lineardata.size();i++){
//	std::cout<<*(result.lineardata[i])<<" ";
//}
//std::cout<<std::endl;
//std::cout<<"About to unlinearize data"<<std::endl;
result.UnlinearizeDataCAPS();


return result;
}



// nproc is the number of processors that share the matrices, and will be involved in the multiplication
template<class Element>
void Matrix<Element>::multiplyInternalCAPS(unique_ptr<Element> **A, unique_ptr<Element> **B, unique_ptr<Element> **C, MatDescriptor desc,
		unique_ptr<Element> *work) const{
	//std::cout<<"In multiplyInternalCAPS, desc.nrec = "<<desc.nrec<<std::endl;
	if (desc.nrec == 0) { // (planned) out of recursion in the data layout, do a regular matrix multiply.  The matrix is now in a 2d block cyclic layout

		// A 2d block cyclic layout with 1 processor still has blocks to deal with
		// run a 1-proc non-strassen
		//printf("Going to call block_multiplyCAPS\n");
		block_multiplyCAPS(A, B, C, desc, work);

	} else {
		if (pattern == NULL) {

			//COUNTERS setExecutionType(desc.nrec, "DFS");
			//printf("Going to start Strassen\n");
			strassenDFSCAPS(A, B, C, desc, work);

		} else {
			if (pattern[0] == 'D' || pattern[0] == 'd') {
				//COUNTERS setExecutionType(desc.nrec, "DFS");
				pattern++;
				//printf("Going to start Strassen with D pattern\n");
				strassenDFSCAPS(A, B, C, desc, work);
				pattern--;
			}
		}

	}
}

template<class Element>
void Matrix<Element>::addMatricesCAPS( int numEntries, unique_ptr<Element> **C, unique_ptr<Element> **A, unique_ptr<Element> **B ) const{
	//COUNTERS increaseAdditions(numEntries);
	//COUNTERS startTimer(TIMER_ADD);
	Element temp;
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ){
    temp = **A[i] + **B[i];
    accessUniquePtr(C[i], temp);
  }
  //COUNTERS stopTimer(TIMER_ADD);
}

template<class Element>
void Matrix<Element>::subMatricesCAPS( int numEntries, unique_ptr<Element> **C, unique_ptr<Element> **A, unique_ptr<Element> **B ) const{
	//COUNTERS increaseAdditions(numEntries);
	//COUNTERS startTimer(TIMER_ADD);
	Element temp;
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ){
    temp = **A[i] - **B[i];
    accessUniquePtr(C[i], temp);
  }
  //COUNTERS stopTimer(TIMER_ADD);
}

template<class Element>
void Matrix<Element>::accessUniquePtr(unique_ptr<Element> *ptr, Element val) const{
	if (*ptr == 0) {
		//std::cout << "Unique_ptr does not already exist" << std::endl;
		*ptr = make_unique<Element>(val);
	} else {
		//std::cout << "!!!UNIQUE PTR ALREADY EXISTS!!!" << std::endl;
		**ptr = val;
	}
}


// useful to improve cache behavior if there is some overlap.  It is safe for T_i to be the same as S_j* as long as i<j.  That is, operations will happen in the order specified
template<class Element>
void Matrix<Element>::tripleSubMatricesCAPS(int numEntries, unique_ptr<Element> **T1, unique_ptr<Element> **S11, unique_ptr<Element> **S12, unique_ptr<Element> **T2,
		unique_ptr<Element> **S21, unique_ptr<Element> **S22, unique_ptr<Element> **T3, unique_ptr<Element> **S31, unique_ptr<Element> **S32) const{
	//COUNTERS increaseAdditions(3*numEntries);
	//COUNTERS startTimer(TIMER_ADD);
	 //std::cout<<"IN TRIPLESUBMATRICESCAPS!!"<<std::endl;
	//printf("numEntries = %d\n",numEntries);
	 Element temp;
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ) {
	  //std::cout<<"i = "<<i<<"**S11[i] = "<<(Element)**S11[i]<<"  **S12[i] = "<<(Element)**S12[i]<<std::endl;
      temp = **S11[i] - **S12[i];
      accessUniquePtr(T1[i], temp);
//      if (*T1[i] == 0){
//    	  std::cout<<"T1 unique_ptr does not already exist"<<std::endl;
//    	  *T1[i] = make_unique<Element>(temp);
//      }else
//    	  **T1[i] = temp;
      //std::cout<<"i = "<<i<<"**T1[i] = "<<(Element)**T1[i]<<std::endl;
      //std::cout<<"i = "<<i<<"**S21[i] = "<<(Element)**S21[i]<<"  **S22[i] = "<<(Element)**S22[i]<<std::endl;
      temp = **S21[i] - **S22[i];
      accessUniquePtr(T2[i], temp);
//      if (*T2[i] == 0){
//    	  std::cout<<"T2 unique_ptr does not already exist"<<std::endl;
//    	  *T2[i] = make_unique<Element>(temp);
//      }else
//    	  **T2[i] = temp;
      //std::cout<<"i = "<<i<<"**T2[i] = "<<(Element)**T2[i]<<std::endl;
      //std::cout<<"i = "<<i<<"**S31[i] = "<<(Element)**S31[i]<<"  **S32[i] = "<<(Element)**S32[i]<<std::endl;
      temp = **S31[i] - **S32[i];
      accessUniquePtr(T3[i], temp);
//      if (*T3[i] == 0){
//    	  std::cout<<"T3 unique_ptr does not already exist"<<std::endl;
//    	  *T3[i] = make_unique<Element>(temp);
//      }else
//    	  **T3[i] = temp;
      //std::cout<<"i = "<<i<<"**T3[i] = "<<(Element)**T3[i]<<std::endl;
  }
  //COUNTERS stopTimer(TIMER_ADD);
}

template<class Element>
void Matrix<Element>::tripleAddMatricesCAPS(int numEntries, unique_ptr<Element> **T1, unique_ptr<Element> **S11, unique_ptr<Element> **S12, unique_ptr<Element> **T2,
		unique_ptr<Element> **S21, unique_ptr<Element> **S22, unique_ptr<Element> **T3, unique_ptr<Element> **S31, unique_ptr<Element> **S32) const{
	//COUNTERS increaseAdditions(3*numEntries);
	//COUNTERS startTimer(TIMER_ADD);
	//printf("In tripleAddMatricesCAPS\n");
	Element temp;
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ) {
      temp = **S11[i] + **S12[i];
      accessUniquePtr(T1[i], temp);
      temp = **S21[i] + **S22[i];
      accessUniquePtr(T2[i], temp);
      temp = **S31[i] + **S32[i];
      accessUniquePtr(T3[i], temp);
  }
  //COUNTERS stopTimer(TIMER_ADD);
}

template<class Element>
void Matrix<Element>::addSubMatricesCAPS(int numEntries, unique_ptr<Element> **T1, unique_ptr<Element> **S11, unique_ptr<Element> **S12, unique_ptr<Element> **T2,
		unique_ptr<Element> **S21, unique_ptr<Element> **S22 ) const{
	//COUNTERS increaseAdditions(2*numEntries);
	//COUNTERS startTimer(TIMER_ADD);
	//std::cout<<"IN ADDSUBMATRICESCAPS!!"<<std::endl;
	Element temp;
#pragma omp parallel for schedule(static, (numEntries+NUM_THREADS-1)/NUM_THREADS)
  for( int i = 0; i < numEntries; i++ ) {
      temp = **S11[i] + **S12[i];
      accessUniquePtr(T1[i], temp);

      temp = **S21[i] - **S22[i];
      accessUniquePtr(T2[i], temp);
  }
  //COUNTERS stopTimer(TIMER_ADD);
}


template<class Element>
void Matrix<Element>::strassenDFSCAPS( unique_ptr<Element> **A, unique_ptr<Element> **B, unique_ptr<Element> **C, MatDescriptor desc, unique_ptr<Element> *workPassThrough ) const{
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

  //printf("numEntriesHalf = %lld\n",numEntriesHalf);
  unique_ptr<Element> **A11 = A;
  unique_ptr<Element> **A21 = A+numEntriesHalf;
  unique_ptr<Element> **A12 = A+2*numEntriesHalf;
  unique_ptr<Element> **A22 = A+3*numEntriesHalf;
  unique_ptr<Element> **B11 = B;
  unique_ptr<Element> **B21 = B+numEntriesHalf;
  unique_ptr<Element> **B12 = B+2*numEntriesHalf;
  unique_ptr<Element> **B22 = B+3*numEntriesHalf;
  unique_ptr<Element> **C11 = C;
  unique_ptr<Element> **C21 = C+numEntriesHalf;
  unique_ptr<Element> **C12 = C+2*numEntriesHalf;
  unique_ptr<Element> **C22 = C+3*numEntriesHalf;

//  for (int i = 0; i < numEntriesHalf; i++){
//	  printf("%d: *(A11[i]) = %f *(A21[i]) = %f  *(A12[i]) = %f *(A22[i]) = %f\n",i, *(A11[i]),*(A21[i]),*(A12[i]),*(A22[i]));
//  }

  lineardata_t R2data;
  lineardata_t R5data;
//  for (int i = 0; i < numEntriesHalf; i++){
//	  //R2data.push_back(0);
//	  //R5data.push_back(0);
//  }

//  R2data.resize(numEntriesHalf);
//  R5data.resize(numEntriesHalf);

  for (size_t elem = 0; elem < numEntriesHalf; ++elem) {
	  unique_ptr<Element> *ptr = new (unique_ptr<Element>);
//	  unique_ptr<Element> uptr = allocZero();
//	  ptr = &uptr;
	  R2data.push_back(ptr);
	  ptr = new (unique_ptr<Element>);
//	  uptr = allocZero();
//	  ptr = &uptr;
	  R5data.push_back(ptr);
  }



  // six registers.  halfDesc is the descriptor for these
  unique_ptr<Element> **R1 = C21;
  unique_ptr<Element> **R2 = &R2data[0];
  unique_ptr<Element> **R3 = C11;
  unique_ptr<Element> **R4 = C22;
  unique_ptr<Element> **R5 = &R5data[0];
  unique_ptr<Element> **R6 = C12;

  unique_ptr<Element> **S5 = R1;
  unique_ptr<Element> **S3 = R2;
  unique_ptr<Element> **S4 = R3;
  tripleSubMatricesCAPS(numEntriesHalf, S5, B22, B12, S3, B12, B11, S4, B22, S3);
  unique_ptr<Element> **T5 = R4;
  unique_ptr<Element> **T3 = R6; // was R1
  addSubMatricesCAPS(numEntriesHalf, T3, A21, A22, T5, A11, A21);
  unique_ptr<Element> **Q5 = R5;
  multiplyInternalCAPS( T5, S5, Q5, halfDesc, workPassThrough);
  unique_ptr<Element> **Q3 = R4;
  multiplyInternalCAPS( T3, S3, Q3, halfDesc, workPassThrough);
  unique_ptr<Element> **T4 = R6;
  subMatricesCAPS(numEntriesHalf, T4, T3, A11);
  unique_ptr<Element> **Q4 = R2;
  multiplyInternalCAPS( T4, S4, Q4, halfDesc, workPassThrough);
  unique_ptr<Element> **T6 = R6;
  subMatricesCAPS(numEntriesHalf, T6, A12, T4);
  unique_ptr<Element> **S7 = R3;
  subMatricesCAPS(numEntriesHalf, S7, S4, B21);
  unique_ptr<Element> **Q7 = R1;
  multiplyInternalCAPS( A22, S7, Q7, halfDesc, workPassThrough);
  unique_ptr<Element> **Q1 = R3;
  multiplyInternalCAPS( A11, B11, Q1, halfDesc, workPassThrough);
  unique_ptr<Element> **U1 = R2;
  unique_ptr<Element> **U2 = R5;
  unique_ptr<Element> **U3 = R2;
  tripleAddMatricesCAPS(numEntriesHalf, U1, Q1, Q4, U2, U1, Q5, U3, U1, Q3);
  addSubMatricesCAPS(numEntriesHalf, C22, U2, Q3, C21, U2, Q7);
  unique_ptr<Element> **Q2 = R5;
  multiplyInternalCAPS( A12, B21, Q2, halfDesc, workPassThrough);
  addMatricesCAPS(numEntriesHalf, C11, Q1, Q2);
  unique_ptr<Element> **Q6 = R5;
  multiplyInternalCAPS(T6, B22, Q6, halfDesc, workPassThrough);
  addMatricesCAPS(numEntriesHalf, C12, U3, Q6);
  //deallocate(R5, numEntriesHalf);
  //deallocate(R2, numEntriesHalf);
  R2data.clear();
  R5data.clear();



}

template<class Element>
void Matrix<Element>::block_multiplyCAPS(unique_ptr<Element> **A,
		unique_ptr<Element> **B, unique_ptr<Element> **C, MatDescriptor d,
		unique_ptr<Element> *work) const{
	long long lda = d.lda;
	//long long lda3 = lda*lda*lda;
	//COUNTERS increaseAdditions( lda3 );
	//COUNTERS increaseMultiplications( lda3 );


	//std::cout<<"C = "<<C<<std::endl;

	//std::cout<<"In block_multiplyCAPS, d.lda = "<<d.lda<<std::endl;

	// do the multiplication, without requiring CC to be zeroed
	//COUNTERS startTimer(TIMER_MUL);
	//square_dgemm_zero( d.lda, AA, BB, CC );
	//COUNTERS stopTimer(TIMER_MUL);
#pragma omp parallel for
	for (int32_t row = 0; row < d.lda; row++) {

		Element temp;

		Element Aval = *allocZero();
		Element Bval = *allocZero();
		for (int32_t col = 0; col < d.lda; col++) {


			//std::cout<<"At start of calc,  temp = "<<temp<<std::endl;
			//std::cout <<"START: C+row+d.lda*col = "<<C+row+d.lda*col<<"  *(C+row+d.lda*col) = "<<*(C+row+d.lda*col)<<" C[row+d.lda*col] = "<<C[row+d.lda*col]<<std::endl;
			for (int32_t i = 0; i < d.lda; i++) {
				//printf("Row %d Col %d i %d\n",row,col,i);
				//printf("Row %d Col %d i %d initial Cval %d Aval %d Bval %d\n",row,col,i,(int)**(C+row*d.lda+col),(int)**(A+d.lda*row+i),(int)**(B+i*d.lda+col));
				//**(C + d.lda * row + col) += **(A + d.lda * row + i)
				//		* **(B + i * d.lda + col);
				Aval = ***(A+row + i * d.lda);  // **(A + d.lda * row + i);
				Bval = ***(B + i + d.lda * col); //  **(B + i * d.lda + col);
				if (i == 0)
					temp = (Aval * Bval);
				else
					temp += (Aval * Bval);
				//std::cout <<"Aval = "<<Aval<<" Bval = "<<Bval<<" temp = "<<temp<<std::endl;
				//printf("Cval(%d,%d) =  %d temp = %d Aval = %d Bval = %d\n",row,col,(int)**(C+row*d.lda+col),(int)temp,(int)Aval,(int)Bval);
			}
			//std::cout <<"row = "<<row<<" col = "<<col<<" temp = "<<(Element)(temp)<<std::endl;

			**(C+row+d.lda*col) = make_unique<Element>(temp);  //**(C + d.lda * row + col) = temp;
			//std::cout <<"END: C+row+d.lda*col = "<<C+row+d.lda*col<<"  *(C+row+d.lda*col) = "<<*(C+row+d.lda*col)<<" C[row+d.lda*col] = "<<C[row+d.lda*col]<<"***(C+row+d.lda*col) "<<***(C+row+d.lda*col)<<std::endl;
		}
	}




//for (int r = 0; r<d.lda;r++){
//	for (int c = 0; c< d.lda;c++){
//		printf("C(%d,%d) = %d\n",r,c,(int)**(C+r*d.lda+c));
//	}
//}
	int len = d.lda * d.lda;
//	for (int r = 0; r < len; r++) {
//		printf("A(%d) = %d B(%d) = %d C(%d) = %d\n", r, (int) **(A + r), r,
//				(int) **(B + r), r, (int) **(C + r));
//	}

}

// get the communicators used for gather and scatter when collapsing/expanding a column or a row

template<class Element>
void Matrix<Element>::sendBlockCAPS( /*MPI_Comm comm,*/int rank, int target,
		unique_ptr<Element> **O, int bs, int source, unique_ptr<Element> **I,
		int ldi) const{
//	printf(
//			"IN SENDBLOCKCAPS, bs = %d ldi = %d rank = %d target = %d source = %d\n",
//			bs, ldi, rank, target, source);

	bool haveILVector2n  = false;
	string elemtype = typeid(**O).name();
	//std::cout<<"In sendBlockCAPS"<<std::endl;
//	if (string::npos != elemtype.find("ILVector2n")){
//		std::cout<<"In sendBlockCAPS, O is an ILVector2n"<<std::endl;
//		haveILVector2n = true;
//	}

	if (source == target) {
		if (rank == source) {
			for (int c = 0; c < bs; c++) {
				for (int i = 0; i < bs; i++) {
//					if (haveILVector2n){
//						ILVector2n dual;
//						dual = **I;
//						*O = make_unique<Element>(dual); //New
//					}
//					else{
//						*O = make_unique<Element>(**I); //New
//					}
					//*O = make_unique<Element>(**I); //New
					*O=*I;
					O++;  //New
					I++;
				}
				//memcpy(O, I, bs * sizeof(unique_ptr<Element> ));
				//O += bs;  //New
				I += ldi - bs;  //New
				//I += ldi; //New
			}
		}
	}
}

template<class Element>
void Matrix<Element>::receiveBlockCAPS(  int rank, int target, unique_ptr<Element> **O, int bs, int source, unique_ptr<Element> **I, int ldo ) const{

	bool haveILVector2n  = false;
	string elemtype = typeid(**O).name();
	//std::cout<<"In receiveBlockCAPS"<<std::endl;
//	if (string::npos != elemtype.find("ILVector2n")){
//		std::cout<<"In receiveBlockCAPS, O is an ILVector2n"<<std::endl;
//		haveILVector2n = true;
//	}



	if (source == target) {
		if (rank == source) {
			for (int c = 0; c < bs; c++) {
				for (int i = 0; i < bs; i++) {
//					if (haveILVector2n){
//						ILVector2n dual;
//						dual = **I;
//						*O = make_unique<Element>(dual); //New
//					}
//					else{
//						*O = make_unique<Element>(**I); //New
//					}
					//*O = make_unique<Element>(**I); //New
					*O=*I;

					I++;
					O++;  //New
				}

				//memcpy( O, I, bs*sizeof(unique_ptr<Element>) );
				//O += ldo; //New
				O += ldo - bs; //New
				//I += bs; //New
			}
		}
	}
}

template <class Element>
void Matrix<Element>::distributeFrom1ProcRecCAPS( MatDescriptor desc, unique_ptr<Element> **O, unique_ptr<Element> **I, int ldi ) const{
  if( desc.nrec == 0 ) { // base case; put the matrix block-cyclic layout
    //MPI_Comm comm = getComm();
    int rank = getRank();
    int bs = desc.bs;
    int numBlocks = desc.lda / bs;
    assert( numBlocks % desc.nprocr == 0 );
    assert( numBlocks % desc.nprocc == 0 );
    assert( (numBlocks / desc.nprocr) % desc.nproc_summa == 0 );
    int nBlocksPerProcRow = numBlocks / desc.nprocr / desc.nproc_summa;
    int nBlocksPerProcCol = numBlocks / desc.nprocc;
    int nBlocksPerBase = numBlocks / desc.nproc_summa;
//    std::cout<<"In distributeFrom1ProcRecCAPS :"<<std::endl;
//    std::cout<<"desc.nproc_summa = "<<desc.nproc_summa<<std::endl;
//    std::cout<<"nBlocksPerProcRow = "<<nBlocksPerProcRow<<std::endl;
//    std::cout<<"desc.nprocr = "<<desc.nprocr<<std::endl;
//    std::cout<<"nBlocksPerProcCol = "<<nBlocksPerProcCol<<std::endl;
//    std::cout<<"desc.nprocc = "<<desc.nprocc<<std::endl;
    for( int sp = 0; sp < desc.nproc_summa; sp++ ) {
      for( int i = 0; i < nBlocksPerProcRow; i++ ) {
	for( int rproc = 0; rproc < desc.nprocr; rproc++ ) {
	  for( int j = 0; j < nBlocksPerProcCol; j++ ) {
	    for( int cproc = 0; cproc < desc.nprocc; cproc++ ) {
	      int source = 0;
	      int target = cproc + rproc*desc.nprocc + sp*base;
	      // row and column of the beginning of the block in I
	      int row = j*(desc.nprocc*bs) + cproc*bs;
	      int col = i*(desc.nprocr*bs) + rproc*bs + sp*nBlocksPerBase*bs;
	      int offsetSource = row + col*ldi;
	      int offsetTarget = (j + i*nBlocksPerProcCol)*bs*bs;
	      sendBlockCAPS( /*comm,*/ rank, target, O+offsetTarget, bs, source, I+offsetSource, ldi );
	    }
	  }
	}
      }
    }
  } else { // recursively call on each of four submatrices
    desc.nrec -= 1;
    desc.lda /= 2;
    int entriesPerQuarter = numEntriesPerProc(desc);
    // top left
    distributeFrom1ProcRecCAPS( desc, O, I, ldi );
    // bottom left
    distributeFrom1ProcRecCAPS( desc, O + entriesPerQuarter, I+desc.lda, ldi );
    // top right
    distributeFrom1ProcRecCAPS( desc, O + 2*entriesPerQuarter, I+desc.lda*ldi, ldi );
    // bottom right
    distributeFrom1ProcRecCAPS( desc, O + 3*entriesPerQuarter, I+desc.lda*ldi+desc.lda, ldi );
  }
}

template <class Element>
void Matrix<Element>::distributeFrom1ProcCAPS( MatDescriptor desc, unique_ptr<Element> **O, unique_ptr<Element> **I ) const{
  distributeFrom1ProcRecCAPS( desc, O, I, desc.lda );
}

template <class Element>
void Matrix<Element>::collectTo1ProcRecCAPS( MatDescriptor desc, unique_ptr<Element>**O, unique_ptr<Element>**I, int ldo ) const{
  if( desc.nrec == 0 ) { // base case; put the matrix block-cyclic layout
    //MPI_Comm comm = getComm();
    int rank = getRank();
    int bs = desc.bs;
    int numBlocks = desc.lda / bs;
    assert( numBlocks % desc.nprocr == 0 );
    assert( numBlocks % desc.nprocc == 0 );
    assert( (numBlocks / desc.nprocr) % desc.nproc_summa == 0 );
    int nBlocksPerProcRow = numBlocks / desc.nprocr / desc.nproc_summa;
    int nBlocksPerProcCol = numBlocks / desc.nprocc;
    int nBlocksPerBase = numBlocks / desc.nproc_summa;
    for( int sp = 0; sp < desc.nproc_summa; sp++ ) {
      for( int i = 0; i < nBlocksPerProcRow; i++ ) {
	for( int rproc = 0; rproc < desc.nprocr; rproc++ ) {
	  for( int j = 0; j < nBlocksPerProcCol; j++ ) {
	    for( int cproc = 0; cproc < desc.nprocc; cproc++ ) {
	      int target = 0;
	      int source = cproc + rproc*desc.nprocc + sp*base;
	      // row and column of the beginning of the block in I
	      int row = j*(desc.nprocc*bs) + cproc*bs;
	      int col = i*(desc.nprocr*bs) + rproc*bs + sp*nBlocksPerBase*bs;
	      int offsetTarget = row + col*ldo;
	      int offsetSource = (j + i*nBlocksPerProcCol)*bs*bs;
	      receiveBlockCAPS( /*comm,*/ rank, target, O+offsetTarget, bs, source, I+offsetSource, ldo );
	    }
	  }
	}
      }
    }
  } else { // recursively call on each of four submatrices
    desc.nrec -= 1;
    desc.lda /= 2;
    int entriesPerQuarter = numEntriesPerProc(desc);
    // top left
    collectTo1ProcRecCAPS( desc, O, I, ldo );
    // bottom left
    collectTo1ProcRecCAPS( desc, O+desc.lda, I + entriesPerQuarter, ldo );
    // top right
    collectTo1ProcRecCAPS( desc, O + desc.lda*ldo, I+2*entriesPerQuarter, ldo );
    // bottom right
    collectTo1ProcRecCAPS( desc, O + desc.lda*ldo+desc.lda, I+3*entriesPerQuarter, ldo );
  }
}

template <class Element>
void Matrix<Element>::collectTo1ProcCAPS( MatDescriptor desc, unique_ptr<Element>**O, unique_ptr<Element> **I ) const{
  collectTo1ProcRecCAPS( desc, O, I, desc.lda );
}


template<class Element>
void Matrix<Element>::ikjalgorithm(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int n) const{
//	string elemtype = typeid(*(Adata[0][0])).name();
//	if (string::npos != elemtype.find("ILVector2n")){
//		std::cout<<"A is an ILVector2n"<<std::endl;
//		(*(Adata[0][0])).PrintValues();
//	}
//	elemtype = typeid(*(Bdata[0][0])).name();
//	if (string::npos != elemtype.find("ILVector2n")){
//		std::cout<<"B is an ILVector2n"<<std::endl;
//		(*(Bdata[0][0])).PrintValues();
//	}
//	//std::cout<<"In ijkalgo"<<std::endl;
	#pragma omp parallel for
	for (int i = 0; i < n; i++) {
        for (int k = 0; k < n; k++) {
            for (int j = 0; j < n; j++) {
                *(Cdata[i][j]) += *(Adata[i][k]) * *(Bdata[k][j]);
            }
        }
    }
}

template<class Element>
void Matrix<Element>::getData(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int row, int inner, int col) const{
	printf("Adata[3][0] = %d\n",(int)(*Adata[3][0]));
	printf("Bdata[3][0] = %d\n",(int)(*Bdata[3][0]));
	printf("Cdata[3][0] = %d\n",(int)(*Cdata[3][0]));
	printf("row = %d inner = %d col = %d\n", row, inner,col);

#pragma omp parallel for
    for (int i = 0; i < row; i++) {
        for (int k = 0; k < inner; k++) {
            for (int j = 0; j < col; j++) {

                *(Cdata[i][j]) += *(Adata[i][k]) * *(Bdata[k][j]);
            }
        }
    }
}

template <class Element>
void Matrix<Element>::allocate_data_t(data_t &A, int outerdim, int innerdim) const {
    A.resize(outerdim);
    for (auto row = A.begin(); row != A.end(); ++row) {
        for (size_t i = 0; i < innerdim; ++i) {
            row->push_back(allocZero());
        }
    }
}

template <class Element>
void Matrix<Element>::strassenR(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int tam) const {
    if (tam <= leafsize) {
        ikjalgorithm(Adata, Bdata, Cdata, tam);
        return;
    }

    // other cases are treated here:
    else {
        int newTam = tam/2;
		data_t
            a11, a12, a21, a22,
            b11, b12, b21, b22,
              c11, c12, c21, c22,
            p1, p2, p3, p4,
            p5, p6, p7,
            aResult, bResult;
allocate_data_t(a11,newTam,newTam);
allocate_data_t(a12,newTam,newTam);
allocate_data_t(a21,newTam,newTam);
allocate_data_t(a22,newTam,newTam);
allocate_data_t(b11,newTam,newTam);
allocate_data_t(b12,newTam,newTam);
allocate_data_t(b21,newTam,newTam);
allocate_data_t(b22,newTam,newTam);
allocate_data_t(c11,newTam,newTam);
allocate_data_t(c12,newTam,newTam);
allocate_data_t(c21,newTam,newTam);
allocate_data_t(c22,newTam,newTam);
allocate_data_t(p1,newTam,newTam);
allocate_data_t(p2,newTam,newTam);
allocate_data_t(p3,newTam,newTam);
allocate_data_t(p4,newTam,newTam);
allocate_data_t(p5,newTam,newTam);
allocate_data_t(p6,newTam,newTam);
allocate_data_t(p7,newTam,newTam);
allocate_data_t(aResult,newTam,newTam);
allocate_data_t(bResult,newTam,newTam);

        int i, j;

        //dividing the matrices in 4 sub-matrices:
        for (i = 0; i < newTam; i++) {
            for (j = 0; j < newTam; j++) {
                *(a11[i][j]) = *(Adata[i][j]);
                *(a12[i][j]) = *(Adata[i][j + newTam]);
                *(a21[i][j]) = *(Adata[i + newTam][j]);
                *(a22[i][j]) = *(Adata[i + newTam][j + newTam]);

                *(b11[i][j]) = *(Bdata[i][j]);
                *(b12[i][j]) = *(Bdata[i][j + newTam]);
                *(b21[i][j]) = *(Bdata[i + newTam][j]);
                *(b22[i][j]) = *(Bdata[i + newTam][j + newTam]);
            }
        }

        // Calculating p1 to p7:

        sum(a11, a22, aResult, newTam); // a11 + a22
        sum(b11, b22, bResult, newTam); // b11 + b22
        strassenR(aResult, bResult, p1, newTam); // p1 = (a11+a22) * (b11+b22)

        sum(a21, a22, aResult, newTam); // a21 + a22
        strassenR(aResult, b11, p2, newTam); // p2 = (a21+a22) * (b11)

        subtract(b12, b22, bResult, newTam); // b12 - b22
        strassenR(a11, bResult, p3, newTam); // p3 = (a11) * (b12 - b22)

        subtract(b21, b11, bResult, newTam); // b21 - b11
        strassenR(a22, bResult, p4, newTam); // p4 = (a22) * (b21 - b11)

        sum(a11, a12, aResult, newTam); // a11 + a12
        strassenR(aResult, b22, p5, newTam); // p5 = (a11+a12) * (b22)

        subtract(a21, a11, aResult, newTam); // a21 - a11
        sum(b11, b12, bResult, newTam); // b11 + b12
        strassenR(aResult, bResult, p6, newTam); // p6 = (a21-a11) * (b11+b12)

        subtract(a12, a22, aResult, newTam); // a12 - a22
        sum(b21, b22, bResult, newTam); // b21 + b22
        strassenR(aResult, bResult, p7, newTam); // p7 = (a12-a22) * (b21+b22)

        // calculating c21, c21, c11 e c22:

        sum(p3, p5, c12, newTam); // c12 = p3 + p5
        sum(p2, p4, c21, newTam); // c21 = p2 + p4

        sum(p1, p4, aResult, newTam); // p1 + p4
        sum(aResult, p7, bResult, newTam); // p1 + p4 + p7
        subtract(bResult, p5, c11, newTam); // c11 = p1 + p4 - p5 + p7

        sum(p1, p3, aResult, newTam); // p1 + p3
        sum(aResult, p6, bResult, newTam); // p1 + p3 + p6
        subtract(bResult, p2, c22, newTam); // c22 = p1 + p3 - p2 + p6

        // Grouping the results obtained in a single matrix:
        for (i = 0; i < newTam ; i++) {
            for (j = 0 ; j < newTam ; j++) {
                *(Cdata[i][j]) = *(c11[i][j]);
                *(Cdata[i][j + newTam]) = *(c12[i][j]);
                *(Cdata[i + newTam][j]) = *(c21[i][j]);
                *(Cdata[i + newTam][j + newTam]) = *(c22[i][j]);
            }
        }
    }
}

template <class Element>
unsigned int Matrix<Element>::nextPowerOfTwo(int n) const {
    return pow(2, int(ceil(log2(n))));
}
//
template <class Element>
void Matrix<Element>::strassen(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, unsigned int n) const {
    //unsigned int n = tam;
    unsigned int m = nextPowerOfTwo(n);

    data_t APrep, BPrep, CPrep;
    allocate_data_t(APrep,m,m);
    allocate_data_t(BPrep,m,m);
    allocate_data_t(CPrep,m,m);


    for(unsigned int i=0; i<n; i++) {
        for (unsigned int j=0; j<n; j++) {
            *(APrep[i][j]) = *(Adata[i][j]);
            *(BPrep[i][j]) = *(Bdata[i][j]);
        }
    }

    strassenR(APrep, BPrep, CPrep, m);
    for(unsigned int i=0; i<n; i++) {
        for (unsigned int j=0; j<n; j++) {
            *(Cdata[i][j]) = *(CPrep[i][j]);
        }
    }
}
//
template <class Element>
void Matrix<Element>::sum(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int tam) const {
    int i, j;

    for (i = 0; i < tam; i++) {
        for (j = 0; j < tam; j++) {
            *(Cdata[i][j]) = *(Adata[i][j]) + *(Bdata[i][j]);
        }
    }
}


template <class Element>
void Matrix<Element>::subtract(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int tam) const{
    int i, j;

    for (i = 0; i < tam; i++) {
        for (j = 0; j < tam; j++) {
            *(Cdata[i][j]) = *(Adata[i][j]) - *(Bdata[i][j]);
        }
    }
}


}

