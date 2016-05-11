// LAYER 2 : LATTICE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
6/1/2015 5:37AM
List of Authors:
TPOC:
Dr. Kurt Rohloff, rohloff@njit.edu
Programmers:
Dr. Yuriy Polyakov, polyakov@njit.edu
Kevin King, kcking@mit.edu
Description:
This code provides basic lattice ideal manipulation functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#ifndef LBCRYPTO_LATTICE_MATRIX_H
#define LBCRYPTO_LATTICE_MATRIX_H

#include <iostream>
#include <functional>
#include <math.h>
#include <stdexcept>
#include <omp.h>
using std::function;
using std::invalid_argument;

#include "largefloat.h"
#include "../math/backend.h"
#include "../math/nbtheory.h"
#include "../math/distrgen.h"
#include "../lattice/ilvector2n.h"
#include "../crypto/lwecrypt.h"
#include "../crypto/lwepre.h"
#include "../utils/inttypes.h"
#include "../utils/utilities.h"
#include "../utils/memory.h"

namespace lbcrypto {

    template<class Element>
        class Matrix {
            typedef vector<vector<unique_ptr<Element>>> data_t;
            typedef function<unique_ptr<Element>(void)> alloc_func;
        public:
            //  Zero constructor
            Matrix(alloc_func allocZero, size_t rows, size_t cols): rows(rows), cols(cols), data(), allocZero(allocZero) {
                data.resize(rows);
                for (auto row = data.begin(); row != data.end(); ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        row->push_back(allocZero());
                    }
                }
            }

            Matrix(const Matrix<Element>& other) : data(), rows(other.rows), cols(other.cols), allocZero(other.allocZero) {
                deepCopyData(other.data);
            }

            inline Matrix<Element>& operator=(const Matrix<Element>& other) {
                rows = other.rows;
                cols = other.cols;
                deepCopyData(other.data);
                return *this;
            }

            inline Matrix<Element>& Ones() {
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        *data[row][col] = 1;
                    }
                }
                return *this;
            }

			//YSP - Removed this definition as it conflicts with FIll(Element val) for int32_t - error is generated in VSS

            //inline Matrix<Element>& Fill(int val) {
            //    for (size_t row = 0; row < rows; ++row) {
            //        for (size_t col = 0; col < cols; ++col) {
            //            *data[row][col] = val;
            //        }
            //    }
            //    return *this;
            //}

            inline Matrix<Element>& Fill(Element val) {
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        *data[row][col] = val;
                    }
                }
                return *this;
            }

            inline Matrix<Element>& Identity() {
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

            /*
             *  Sets the first row to be powers of two
             */
            inline Matrix<Element> GadgetVector() const {
                Matrix<Element> g(allocZero, rows, cols);
                auto two = allocZero();
                *two = 2;
                g(0, 0) = 1;
                for (size_t col = 1; col < cols; ++col) {
                    g(0, col) = g(0, col-1) * *two;
                }
                return g;
            }

            inline double Norm() const {
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

            inline Matrix<Element> Mult(Matrix<Element> const& other) const {
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


                for (size_t row = 0; row < result.rows; ++row) {

	          //if result was zero allocated the following should not be needed
	          for (size_t col = 0; col < result.cols; ++col) { 
	      	      *result.data[row][col] = 0;
	          }
	          for (size_t i = 0; i < cols; ++i) {
                    for (size_t col = 0; col < result.cols; ++col) {
                            *result.data[row][col] += *data[row][i] * *other.data[i][col];
                        }
                    }
                }
#endif
                return result;
            }

            inline Matrix<Element> operator*(Matrix<Element> const& other) const {
                return Mult(other);
            }

            inline Matrix<Element> ScalarMult(Element const& other) const {
                Matrix<Element> result(*this);
#if 0
                for (size_t row = 0; row < result.rows; ++row) {
                    for (size_t col = 0; col < result.cols; ++col) {
                        *result.data[row][col] = *result.data[row][col] * other;
                    }
                }
#else
                #pragma omp parallel for
		for (size_t col = 0; col < result.cols; ++col) {
	            for (size_t row = 0; row < result.rows; ++row) {

                        *result.data[row][col] = *result.data[row][col] * other;
                    }
                }

#endif
                return result;
            }

            inline Matrix<Element> operator*(Element const& other) const {
                return ScalarMult(other);
            }

            inline bool Equal(Matrix<Element> const& other) const {
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

            inline bool operator==(Matrix<Element> const& other) const {
                return Equal(other);
            }

            inline bool operator!=(Matrix<Element> const& other) const {
                return !Equal(other);
            }

            const data_t& GetData() const {
                return data;
            }

            size_t GetRows() const {
                return rows;
            }
            size_t GetCols() const {
                return cols;
            }
            alloc_func GetAllocator() const {
                return allocZero;
            }

            void SetFormat(Format format) {
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        data[row][col]->SetFormat(format);
                    }
                }
            }

            inline Matrix<Element> Add(Matrix<Element> const& other) const {
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
		for (size_t j = 0; j < cols; ++j) {
		  for (size_t i = 0; i < rows; ++i) {
                        *result.data[i][j] += *other.data[i][j];
                    }
                }
#endif
                return result;
            }

            inline Matrix<Element> operator+(Matrix<Element> const& other) const {
                return this->Add(other);
            }

            inline Matrix<Element>& operator+=(Matrix<Element> const& other) {
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

            inline Matrix<Element> Sub(Matrix<Element> const& other) const {
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
		for (size_t j = 0; j < cols; ++j) {
	            for (size_t i = 0; i < rows; ++i) {
                        *result.data[i][j] = *data[i][j] - *other.data[i][j];
                    }
                }
#endif

                return result;
            }

            inline Matrix<Element> operator-(Matrix<Element> const& other) const {
                return this->Sub(other);
            }

            inline Matrix<Element>& operator-=(Matrix<Element> const& other) {
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

            inline Matrix<Element> Transpose() const {
                Matrix<Element> result(allocZero, cols, rows);
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        result(col, row) = (*this)(row, col);
                    }
                }
                return result;
            }

            //  add rows to bottom of the matrix
            inline Matrix<Element>& VStack(Matrix<Element> const& other) {
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
            inline Matrix<Element>& HStack(Matrix<Element> const& other) {
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

            inline Element& operator()(size_t row, size_t col) {
                return *data[row][col];
            }

            inline Element const& operator()(size_t row, size_t col) const {
                return *data[row][col];
            }

            void PrintValues() const {
                for (size_t col = 0; col < cols; ++col) {
                    for (size_t row = 0; row < rows; ++row) {
                        data[row][col]->PrintValues();
                        std::cout << " ";
                    }
                    std::cout << std::endl;
                }
            }


            inline void SwitchFormat() {

    				for (size_t row = 0; row < rows; ++row) {
    					for (size_t col = 0; col < cols; ++col) {
    						data[row][col]->SwitchFormat();
    					}
    				}

            }


        private:
            data_t data;
            size_t rows;
            size_t cols;
            alloc_func allocZero;
            void deepCopyData(data_t const& src) {
                data.clear();
                data.resize(src.size());
                for (size_t row = 0; row < src.size(); ++row) {
                    for (auto elem = src[row].begin(); elem != src[row].end(); ++elem) {
                        data[row].push_back(make_unique<Element>(**elem));
                    }
                }
            }
        };
    template<class Element>
        inline Matrix<Element> operator*(Element const& e, Matrix<Element> const& M) {
            return M.ScalarMult(e);
        }

    inline Matrix<BigBinaryInteger> Rotate(Matrix<ILVector2n> const& inMat) {
        Matrix<ILVector2n> mat(inMat);
        mat.SetFormat(COEFFICIENT);
        size_t n = mat(0,0).GetLength();
        BigBinaryInteger const& modulus = mat(0,0).GetParams().GetModulus();
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
    inline Matrix<BigBinaryVector> RotateVecResult(Matrix<ILVector2n> const& inMat) {
        Matrix<ILVector2n> mat(inMat);
        mat.SetFormat(COEFFICIENT);
        size_t n = mat(0,0).GetLength();
        BigBinaryInteger const& modulus = mat(0,0).GetParams().GetModulus();
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
    inline Matrix<LargeFloat> Cholesky(const Matrix<int32_t> &input) {
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
                    result(i, j) = result(i, j) - result(i, k) * result(j, k);
                    //result(i, j) = input(i, j) - result(i, k) * result(j, k);
                }
            }
        }
        return result;
    }

    //  Convert from Z_q to [-q/2, q/2]
    inline Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryInteger> &input, const BigBinaryInteger& modulus) {
        size_t rows = input.GetRows();
        size_t cols = input.GetCols();
        BigBinaryInteger negativeThreshold(modulus / BigBinaryInteger::TWO);
        Matrix<int32_t> result([](){ return make_unique<int32_t>(); }, rows, cols);
        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                if (input(i,j) > negativeThreshold) {
                    result(i,j) = -(modulus - input(i,j)).ConvertToInt();
                } else {
                    result(i,j) = input(i,j).ConvertToInt();
                }
            }
        }
        return result;
    }

    inline Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryVector> &input, const BigBinaryInteger& modulus) {
        size_t rows = input.GetRows();
        size_t cols = input.GetCols();
        BigBinaryInteger negativeThreshold(modulus / BigBinaryInteger::TWO);
        Matrix<int32_t> result([](){ return make_unique<int32_t>(); }, rows, cols);
        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                const BigBinaryInteger& elem = input(i,j).GetValAtIndex(0);
                if (elem > negativeThreshold) {
                    result(i,j) = -(modulus - elem).ConvertToInt();
                } else {
                    result(i,j) = elem.ConvertToInt();
                }
            }
        }
        return result;
    }

    //  split a vector of int32_t into a vector of ring elements with ring dimension n
    inline Matrix<ILVector2n> SplitInt32IntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const ILParams &params) {
			
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
    inline Matrix<ILVector2n> SplitInt32AltIntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const ILParams &params) {
			
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

}
#endif // LBCRYPTO_LATTICE_MATRIX_H
