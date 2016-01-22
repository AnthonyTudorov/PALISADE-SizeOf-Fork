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

using std::function;

#include "largefloat.h"
#include "../../src/math/backend.h"
#include "../../src/math/nbtheory.h"
#include "../../src/math/distrgen.h"
#include "../../src/lattice/ilvector2n.h"
#include "../../src/crypto/lwecrypt.h"
#include "../../src/crypto/lwepre.h"
#include "../../src/utils/inttypes.h"
#include "../../src/utils/utilities.h"
#include "../../src/utils/memory.h"

namespace lbcrypto {

    template<class Element>
        class ILMat {
            typedef vector<vector<unique_ptr<Element>>> data_t;
            typedef function<unique_ptr<Element>(void)> alloc_func;
        public:
            //  Zero constructor
            ILMat(alloc_func allocZero, size_t rows, size_t cols): rows(rows), cols(cols), data(), allocZero(allocZero) {
                data.resize(rows);
                for (auto row = data.begin(); row != data.end(); ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        row->push_back(allocZero());
                    }
                }
            }

            ILMat(const ILMat<Element>& other) : data(), rows(other.rows), cols(other.cols), allocZero(other.allocZero) {
                deepCopyData(other.data);
            }

            inline ILMat<Element>& operator=(const ILMat<Element>& other) {
                rows = other.rows;
                cols = other.cols;
                deepCopyData(other.data);
                return *this;
            }

            inline ILMat<Element>& Ones() {
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        *data[row][col] = 1;
                    }
                }
                return *this;
            }

			//YSP - Removed this definition as it conflicts with FIll(Element val) for int32_t - error is generated in VSS

            //inline ILMat<Element>& Fill(int val) {
            //    for (size_t row = 0; row < rows; ++row) {
            //        for (size_t col = 0; col < cols; ++col) {
            //            *data[row][col] = val;
            //        }
            //    }
            //    return *this;
            //}

            inline ILMat<Element>& Fill(Element val) {
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        *data[row][col] = val;
                    }
                }
                return *this;
            }

            inline ILMat<Element>& Identity() {
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
            inline ILMat<Element> GadgetVector() const {
                ILMat<Element> g(allocZero, rows, cols);
                auto two = allocZero();
                *two = 2;
                g(0, 0) = 1;
                for (size_t col = 1; col < cols; ++col) {
                    g(0, col) = g(0, col-1) * *two;
                }
                return g;
            }

            inline ILMat<Element> Mult(ILMat<Element> const& other) const {
                if (cols != other.rows) {
                    throw "incompatible matrix multiplication";
                }
                ILMat<Element> result(allocZero, rows, other.cols);
                for (size_t row = 0; row < result.rows; ++row) {
                    for (size_t col = 0; col < result.cols; ++col) {
                        for (size_t i = 0; i < cols; ++i) {
                            *result.data[row][col] += *data[row][i] * *other.data[i][col];
                        }
                    }
                }
                return result;
            }

            inline ILMat<Element> operator*(ILMat<Element> const& other) const {
                return Mult(other);
            }

            inline ILMat<Element> ScalarMult(Element const& other) const {
                ILMat<Element> result(*this);
                for (size_t row = 0; row < result.rows; ++row) {
                    for (size_t col = 0; col < result.cols; ++col) {
                        *result.data[row][col] = *result.data[row][col] * other;
                    }
                }
                return result;
            }

            inline ILMat<Element> operator*(Element const& other) const {
                return ScalarMult(other);
            }

            inline bool Equal(ILMat<Element> const& other) const {
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

            inline bool operator==(ILMat<Element> const& other) const {
                return Equal(other);
            }

            inline bool operator!=(ILMat<Element> const& other) const {
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

            void SetFormat(Format format) {
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        data[row][col]->SetFormat(format);
                    }
                }
            }

            inline ILMat<Element> Add(ILMat<Element> const& other) const {
                if (rows != other.rows || cols != other.cols) {
                    throw "Addition operands have incompatible dimensions";
                }
                ILMat<Element> result(*this);
                for (size_t i = 0; i < rows; ++i) {
                    for (size_t j = 0; j < cols; ++j) {
                        *result.data[i][j] += *other.data[i][j];
                    }
                }
                return result;
            }

            inline ILMat<Element> operator+(ILMat<Element> const& other) const {
                return this->Add(other);
            }

            inline ILMat<Element>& operator+=(ILMat<Element> const& other) {
                if (rows != other.rows || cols != other.cols) {
                    throw "Addition operands have incompatible dimensions";
                }
                for (size_t i = 0; i < rows; ++i) {
                    for (size_t j = 0; j < cols; ++j) {
                        data[i][j] += *other.data[i][j];
                    }
                }
                return *this;
            }

            inline ILMat<Element> Sub(ILMat<Element> const& other) const {
                if (rows != other.rows || cols != other.cols) {
                    throw "Subtraction operands have incompatible dimensions";
                }
                ILMat<Element> result(allocZero, rows, other.cols);
                for (size_t i = 0; i < rows; ++i) {
                    for (size_t j = 0; j < cols; ++j) {
                        *result.data[i][j] = *data[i][j] - *other.data[i][j];
                    }
                }
                return result;
            }

            inline ILMat<Element> operator-(ILMat<Element> const& other) const {
                return this->Sub(other);
            }

            inline ILMat<Element>& operator-=(ILMat<Element> const& other) {
                if (rows != other.rows || cols != other.cols) {
                    throw "Subtraction operands have incompatible dimensions";
                }
                for (size_t i = 0; i < rows; ++i) {
                    for (size_t j = 0; j < cols; ++j) {
                        *data[i][j] -= *other.data[i][j];
                    }
                }
                return *this;
            }

            inline ILMat<Element> Transpose() const {
                ILMat<Element> result(allocZero, cols, rows);
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        result(col, row) = (*this)(row, col);
                    }
                }
                return result;
            }

            //  add rows to bottom of the matrix
            inline ILMat<Element>& VStack(ILMat<Element> const& other) {
                if (cols != other.cols) {
                    throw "VStack rows not equal size";
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
            inline ILMat<Element>& HStack(ILMat<Element> const& other) {
                if (rows != other.rows) {
                    throw "HStack cols not equal size";
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
            /*
               BigBinaryInteger& Norm() const {
               BigBinaryInteger& norm = 0;
               BigBinaryInteger& norm_t = 0;
               for (size_t col = 0; col < cols; ++col) {
               for (size_t row = 0; row < rows; ++row) {
               norm_t = data[row][col]->Norm();
               if norm_t > norm {
               norm = norm_t;
               }
               }
               }
               return norm;
               }
               */

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
        inline ILMat<Element> operator*(Element const& e, ILMat<Element> const& M) {
            return M.ScalarMult(e);
        }

    /**
     *  Each element becomes a square matrix with columns of that element's
     *  rotations in coefficient form.
     */
    inline ILMat<BigBinaryInteger> Rotate(ILMat<ILVector2n> const& inMat) {
        ILMat<ILVector2n> mat(inMat);
        mat.SetFormat(COEFFICIENT);
        size_t n = mat(0,0).GetLength();
        BigBinaryInteger const& modulus = mat(0,0).GetParams().GetModulus();
        size_t rows = mat.GetRows() * n;
        size_t cols = mat.GetCols() * n;
        ILMat<BigBinaryInteger> result(BigBinaryInteger::Allocator, rows, cols);
        for (size_t row = 0; row < mat.GetRows(); ++row) {
            for (size_t col = 0; col < mat.GetCols(); ++col) {
                for (size_t rotRow = 0; rotRow < n; ++rotRow) {
                    for (size_t rotCol = 0; rotCol < n; ++rotCol) {
                        BigBinaryInteger& elem = result(row*n + rotRow, col*n + rotCol);
                        elem =
                            mat(row, col).GetValues().GetValAtIndex(
                                (rotRow - rotCol + n) % n
                                );
                        //  negate (mod q) upper-right triangle to account for
                        //  (mod x^n + 1)
                        if (rotRow < rotCol) {
                            elem =
                                modulus.ModSub(
                                    elem,
                                    modulus);
                        }
                    }
                }
            }
        }
        return result;
    }
    template<class Element>
        inline std::ostream& operator<<(std::ostream& os, const ILMat<Element>& m){
            os << "[ ";
            for (size_t row = 0; row < m.GetRows(); ++row) {
                os << "[ ";
                for (size_t col = 0; col < m.GetCols(); ++col) {
                    os << *m.GetData()[row][col];
                }
                os << " ]\n";
            }
            os << " ]\n";
            return os;
        }

    // YSP removed the ILMat class because it is not defined for all possible data types
    // needs to be checked to make sure input matrix is used in the right places
    // the assumption is that covariance matrix does not have large coefficients because it is formed by
    // discrete gaussians e and s; this implies int32_t can be used
    // This algorithm can be further improved - see the Darmstadt paper section 4.4
    inline ILMat<LargeFloat> Cholesky(const ILMat<int32_t> &input) {
        //  http://eprint.iacr.org/2013/297.pdf
        if (input.GetRows() != input.GetCols()) {
            throw "not square";
        }
        size_t rows = input.GetRows();
        ILMat<LargeFloat> result([](){ return make_unique<LargeFloat>(); }, rows, rows);

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
    inline ILMat<int32_t> ConvertToInt32(const ILMat<BigBinaryInteger> &input, const BigBinaryInteger& modulus) {
        size_t rows = input.GetRows();
        size_t cols = input.GetCols();
        BigBinaryInteger negativeThreshold(modulus / BigBinaryInteger::TWO);
        ILMat<int32_t> result([](){ return make_unique<int32_t>(); }, rows, cols);
        for (size_t i = 0; i < rows; ++i) {
            for (size_t j = 0; j < cols; ++j) {
                if (input(i,j) > negativeThreshold) {
                    result(i,j) = (modulus - input(i,j)).ConvertToInt();
                } else {
                    result(i,j) = input(i,j).ConvertToInt();
                }
            }
        }
        return result;
    }

}
#endif // LBCRYPTO_LATTICE_MATRIX_H
