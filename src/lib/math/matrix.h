/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
v00.01
Last Edited:
5/11/2016 5:37AM
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
#ifndef LBCRYPTO_MATH_MATRIX_H
#define LBCRYPTO_MATH_MATRIX_H

#include <iostream>
#include <functional>
#include <math.h>
#include <stdexcept>
#include <omp.h>
//using std::function;

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
            typedef std::function<unique_ptr<Element>(void)> alloc_func;
        public:
            //  Zero constructor
            Matrix(alloc_func allocZero, size_t rows, size_t cols); 

            Matrix(const Matrix<Element>& other);

            inline Matrix<Element>& operator=(const Matrix<Element>& other);

            inline Matrix<Element>& Ones();  

            inline Matrix<Element>& Fill(Element val); 

            inline Matrix<Element>& Identity();

            /*
             *  Sets the first row to be powers of two
             */
            inline Matrix<Element> GadgetVector() const; 

            inline double Norm() const;

            inline Matrix<Element> Mult(Matrix<Element> const& other) const;

            inline Matrix<Element> operator*(Matrix<Element> const& other) const {
                return Mult(other);
            }

            inline Matrix<Element> ScalarMult(Element const& other) const; 

            inline Matrix<Element> operator*(Element const& other) const {
                return ScalarMult(other);
            }

            inline bool Equal(Matrix<Element> const& other) const; 

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

            void SetFormat(Format format); 

            inline Matrix<Element> Add(Matrix<Element> const& other) const;

            inline Matrix<Element> operator+(Matrix<Element> const& other) const {
                return this->Add(other);
            }

            inline Matrix<Element>& operator+=(Matrix<Element> const& other);

            inline Matrix<Element> Sub(Matrix<Element> const& other) const; 

            inline Matrix<Element> operator-(Matrix<Element> const& other) const {
                return this->Sub(other);
            }

            inline Matrix<Element>& operator-=(Matrix<Element> const& other);

            inline Matrix<Element> Transpose() const;

            //  add rows to bottom of the matrix
            inline Matrix<Element>& VStack(Matrix<Element> const& other);

            //  add cols to right of the matrix
            inline Matrix<Element>& HStack(Matrix<Element> const& other);

            inline Element& operator()(size_t row, size_t col) {
                return *data[row][col];
            }

            inline Element const& operator()(size_t row, size_t col) const {
                return *data[row][col];
            }

            void PrintValues() const; 

            inline void SwitchFormat(); 

        private:
            data_t data;
            size_t rows;
            size_t cols;
            alloc_func allocZero;
            void deepCopyData(data_t const& src);
        };

    template<class Element>
    inline Matrix<Element> operator*(Element const& e, Matrix<Element> const& M) {
        return M.ScalarMult(e);
    }

    inline Matrix<BigBinaryInteger> Rotate(Matrix<ILVector2n> const& inMat);

    /**
     *  Each element becomes a square matrix with columns of that element's
     *  rotations in coefficient form.
     */
    inline Matrix<BigBinaryVector> RotateVecResult(Matrix<ILVector2n> const& inMat);

    template<class Element>
    inline std::ostream& operator<<(std::ostream& os, const Matrix<Element>& m);

    // YSP removed the Matrix class because it is not defined for all possible data types
    // needs to be checked to make sure input matrix is used in the right places
    // the assumption is that covariance matrix does not have large coefficients because it is formed by
    // discrete gaussians e and s; this implies int32_t can be used
    // This algorithm can be further improved - see the Darmstadt paper section 4.4
	//  http://eprint.iacr.org/2013/297.pdf
    inline Matrix<LargeFloat> Cholesky(const Matrix<int32_t> &input); 

    //  Convert from Z_q to [-q/2, q/2]
    inline Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryInteger> &input, const BigBinaryInteger& modulus);

    inline Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryVector> &input, const BigBinaryInteger& modulus); 

    //  split a vector of int32_t into a vector of ring elements with ring dimension n
    inline Matrix<ILVector2n> SplitInt32IntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const ILParams &params); 

	//  split a vector of BBI into a vector of ring elements with ring dimension n
    inline Matrix<ILVector2n> SplitInt32AltIntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const ILParams &params); 

}
#endif // LBCRYPTO_MATH_MATRIX_H
