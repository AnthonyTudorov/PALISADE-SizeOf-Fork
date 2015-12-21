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
        public:
            //  concat

            //  Zero constructor
            ILMat(ILParams params, Format format, size_t rows, size_t cols): params(make_unique<ILParams>(params)), format(format), rows(rows), cols(cols), data() {
                data.resize(rows);
                for (auto row = data.begin(); row != data.end(); ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        row->push_back(make_unique<Element>(params, format));
                    }
                }
            }

            ILMat(const ILMat<Element>& other) : params(make_unique<ILParams>(*other.params)), format(other.format), data(), rows(other.rows), cols(other.cols) {
                deepCopyData(other.data);
            }

            inline ILMat<Element>& operator=(const ILMat<Element>& other) {
                format = other.format;
                params = make_unique<ILParams>(*other.params);
                rows = other.rows;
                cols = other.cols;
                deepCopyData(other.data);
                return *this;
            }

            inline static ILMat<Element> Ones(ILParams params, Format format, size_t rows, size_t cols) {
                ILMat m(params, format, rows, cols);
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        m.data[row][col]->SetValAtIndex(0, 1);
                    }
                }
                return m;
            }

            inline void Fill(int val) {
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        data[row][col]->SetValAtIndex(0, val);
                    }
                }
            }

            inline static ILMat<Element> Identity(ILParams params, Format format, size_t rows, size_t cols) {
                ILMat m(params, format, rows, cols);
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        if (row == col) {
                            m.data[row][col]->SetValAtIndex(0, 1);
                        }
                    }
                }
                return m;
            }

            inline ILMat<Element> Mult(ILMat<Element> const& other) const {
                if (cols != other.rows) {
                    throw "incompatible matrix multiplication";
                }
                ILMat<Element> result(*params, format, rows, other.cols);
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

            inline bool Equal(ILMat<Element> const& other) const {
                if (rows != other.rows || cols != other.cols) {
                    return false;
                }
                if (format != other.format) {
                    return false;
                }
                if (*params != *other.params) {
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
                if (*this->format != format) {
                    for (size_t row = 0; row < rows; ++row) {
                        for (size_t col = 0; col < cols; ++col) {
                            data[row][col]->SwitchFormat();
                        }
                    }
                    *this->format = format;
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
                ILMat<Element> result(*params, format, rows, other.cols);
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

            inline ILMat<Element>& Transpose() {
                ILMat<Element> copy(*this);
                std::swap<size_t>(cols, rows);
                data.clear();
                data.resize(rows);
                for (size_t row = 0; row < rows; ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        data[row].push_back(make_unique<Element>(*copy.data[col][row]));
                    }
                }
                return *this;
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

        private:
            data_t data;
            size_t rows;
            size_t cols;
            unique_ptr<ILParams> params;
            Format format;
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

}
#endif // LBCRYPTO_LATTICE_MATRIX_H
