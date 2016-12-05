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
#ifndef LBCRYPTO_MATH_MATRIX_H
#define LBCRYPTO_MATH_MATRIX_H
#include "dgemm-blas.h"
#include "CAPSutils.h"
#include <assert.h>
#include <stdlib.h>

#include <typeinfo>
#include <string>
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
            typedef vector<unique_ptr<Element>> lineardata_t;
            typedef typename vector<unique_ptr<Element>>::iterator it_lineardata_t;
            typedef std::function<unique_ptr<Element>(void)> alloc_func;
        
        public:

			/**
			 * Constructor that initializes matrix values using a zero allocator
			 *
			 * @param &allocZero lambda function for zero initialization.
			 * @param &rows number of rows.
			 * @param &rows number of columns.
			 */
            Matrix(alloc_func allocZero, size_t rows, size_t cols);

			/**
			 * Constructor that initializes matrix values using a distribution generation allocator
			 *
			 * @param &allocZero lambda function for zero initialization (used for initializing derived matrix objects)
			 * @param &rows number of rows.
			 * @param &rows number of columns.
			 * @param &allocGen lambda function for intialization using a distribution generator.
			 */
            Matrix(alloc_func allocZero, size_t rows, size_t cols, alloc_func allocGen);

			/**
			 * Copy constructor
			 *
			 * @param &other the matrix object to be copied
			 */
            Matrix(const Matrix<Element>& other);


			/**
			 * Assignment operator
			 *
			 * @param &other the matrix object whose values are to be copied
			 * @return the resulting matrix
			 */
            inline Matrix<Element>& operator=(const Matrix<Element>& other);

			/**
			 * In-place change of the current matrix to a matrix of all ones
			 *
			 * @return the resulting matrix
			 */
            inline Matrix<Element>& Ones();  

			/**
			 * Fill matrix using the same element
			 *
			 * @param &val the element the matrix is filled by
			 *
			 * @return the resulting matrix
			 */
            inline Matrix<Element>& Fill(Element val); 

			/**
			 * In-place change of the current matrix to Identity matrix
			 *
			 * @return the resulting matrix
			 */
            inline Matrix<Element>& Identity();

            /**
             * Sets the first row to be powers of two
			 *
			 * @return the resulting matrix
             */
            inline Matrix<Element> GadgetVector() const; 

            /**
             * Computes the infinity norm
			 *
			 * @return the norm in double format
             */            
			inline double Norm() const;

            /**
             * Matrix multiplication
			 *
			 * @param &other the multiplier matrix
			 * @return the result of multiplication
             */  
            inline Matrix<Element> Mult(Matrix<Element> const& other) const;

            /**
             * Operator for matrix multiplication
			 *
			 * @param &other the multiplier matrix
			 * @return the result of multiplication
             */  
            inline Matrix<Element> operator*(Matrix<Element> const& other) const {
                return Mult(other);
            }

            /**
             * Multiplication of matrix by a scalar
			 *
			 * @param &other the multiplier element
			 * @return the result of multiplication
             */  
            inline Matrix<Element> ScalarMult(Element const& other) const; 

            /**
             * Operator for scalar multiplication
			 *
			 * @param &other the multiplier element
			 * @return the result of multiplication
             */ 
            inline Matrix<Element> operator*(Element const& other) const {
                return ScalarMult(other);
            }

            /**
             * Equality check
			 *
			 * @param &other the matrix object to compare to
			 * @return the boolean result
             */ 
            inline bool Equal(Matrix<Element> const& other) const; 

            /**
             * Operator for equality check
			 *
			 * @param &other the matrix object to compare to
			 * @return the boolean result
             */ 
            inline bool operator==(Matrix<Element> const& other) const {
                return Equal(other);
            }

            /**
             * Operator for non-equality check
			 *
			 * @param &other the matrix object to compare to
			 * @return the boolean result
             */ 
            inline bool operator!=(Matrix<Element> const& other) const {
                return !Equal(other);
            }

            /**
             * Get property to access the data as a vector of vectors
			 *
			 * @return the data as vector of vectors
             */ 
            const data_t& GetData() const {
                return data;
            }

//            const data_t& GetLinearData() const {
//                return lineardata;
//            }

            /**
             * Get property to access the number of rows in the matrix
			 *
			 * @return the number of rows
             */ 
            size_t GetRows() const {
                return rows;
            }

            /**
             * Get property to access the number of columns in the matrix
			 *
			 * @return the number of columns
             */ 
            size_t GetCols() const {
                return cols;
			}

            /**
             * Get property to access the zero allocator for the matrix
			 *
			 * @return the lambda function corresponding to the element zero allocator
             */ 
            alloc_func GetAllocator() const {
                return allocZero;
            }

            /**
             * Sets the evaluation or coefficient representation for all ring elements that support the SetFormat method
			 *
			 * @param &format the enum value corresponding to coefficient or evaluation representation
             */ 
            void SetFormat(Format format); 


            /**
             * Matrix addition
			 *
			 * @param &other the matrix to be added
			 * @return the resulting matrix
             */ 
            inline Matrix<Element> Add(Matrix<Element> const& other) const;

            /**
             * Operator for matrix addition
			 *
			 * @param &other the matrix to be added
			 * @return the resulting matrix
             */ 
            inline Matrix<Element> operator+(Matrix<Element> const& other) const {
                return this->Add(other);
            }

            /**
             * Operator for in-place addition
			 *
			 * @param &other the matrix to be added
			 * @return the resulting matrix (same object)
             */ 
            inline Matrix<Element>& operator+=(Matrix<Element> const& other);

            /**
             * Matrix substraction
			 *
			 * @param &other the matrix to be substracted
			 * @return the resulting matrix
             */ 
            inline Matrix<Element> Sub(Matrix<Element> const& other) const; 

            /**
             * Operator for matrix substraction
			 *
			 * @param &other the matrix to be substracted
			 * @return the resulting matrix
             */ 
            inline Matrix<Element> operator-(Matrix<Element> const& other) const {
                return this->Sub(other);
            }

            /**
             * Operator for in-place matrix substraction
			 *
			 * @param &other the matrix to be substracted
			 * @return the resulting matrix (same object)
             */ 
            inline Matrix<Element>& operator-=(Matrix<Element> const& other);

            /**
             * Matrix transposition
			 *
			 * @return the resulting matrix
             */ 
            inline Matrix<Element> Transpose() const;

            /**
             * Add rows to bottom of the matrix
			 *
			 * @param &other the matrix to be added to the bottom of current matrix
			 * @return the resulting matrix
             */ 
            inline Matrix<Element>& VStack(Matrix<Element> const& other);

            /**
             * Add columns the right of the matrix
			 *
			 * @param &other the matrix to be added to the right of current matrix
			 * @return the resulting matrix
             */ 
            inline Matrix<Element>& HStack(Matrix<Element> const& other);

            /**
             * Matrix indexing operator - writeable instance of the element
			 *
			 * @param &row row index
			 * @param &col column index
			 * @return the element at the index
             */ 
            inline Element& operator()(size_t row, size_t col) {
                return *data[row][col];
            }

            /**
             * Matrix indexing operator - read-only instance of the element
			 *
			 * @param &row row index
			 * @param &col column index
			 * @return the element at the index
             */ 
            inline Element const& operator()(size_t row, size_t col) const {
                return *data[row][col];
            }

            /**
             * Print values of the matrix to the cout stream
			 *
             */ 
            void PrintValues() const; 

            /**
             * Call switch format for each (ring) element
			 *
             */ 
            inline void SwitchFormat(); 

//            it_lineardata_t  allocate( long long int s );
//            void deallocate( it_lineardata_t A, long long s );
            Matrix<Element> MultiplyCAPS(const Matrix<Element>& other, int nrec=0) const;
            Matrix<Element> MultiplyStrassen(const Matrix<Element>& other,int leafsize) const;
            void PrintLinearDataCAPS(it_lineardata_t elem) const;

            void multiplyInternalCAPS( it_lineardata_t A, it_lineardata_t B, it_lineardata_t C, MatDescriptor desc, it_lineardata_t work ) const;
            void strassenDFSCAPS( it_lineardata_t A, it_lineardata_t B, it_lineardata_t C, MatDescriptor desc, it_lineardata_t workPassThrough ) const;
            void block_multiplyCAPS( it_lineardata_t A, it_lineardata_t B, it_lineardata_t C, MatDescriptor d, it_lineardata_t workPassThrough ) const;
            void LinearizeDataCAPS(lineardata_t *lineardataPtr) const;
            void UnlinearizeDataCAPS(lineardata_t *lineardataPtr) const;
        private:
            mutable data_t data;
            mutable int leafsize = 256;
            //mutable lineardata_t lineardata;
            size_t rows;
            mutable int rowpad = 0;
            size_t cols;
            mutable int colpad = 0;
            alloc_func allocZero;
            mutable char *pattern = NULL;
            mutable int numAdd = 0;
            mutable int numMult = 0;
            mutable int numSub = 0;
            mutable MatDescriptor desc;
            mutable unique_ptr<Element> zeroUniquePtr = allocZero();
			//deep copy of data - used for copy constructor
            void deepCopyData(data_t const& src);
            void getData(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int row, int inner, int col) const;
            void strassen(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, unsigned int n) const;
            unsigned int nextPowerOfTwo(int n) const;
            void strassenR(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int tam) const;
            void allocate_data_t(data_t &A, int outerdim, int innerdim) const;
            void sum(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int tam) const;
            void subtract(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int tam) const;
            void ikjalgorithm(const data_t &Adata, const data_t &Bdata, const data_t &Cdata, int n) const;
            void accessUniquePtr(it_lineardata_t ptr, Element val) const;
            void smartSubtraction(it_lineardata_t result, it_lineardata_t A, it_lineardata_t B) const;

            void smartAddition(it_lineardata_t result, it_lineardata_t A, it_lineardata_t B) const;
            void addMatricesCAPS( int numEntries, it_lineardata_t C, it_lineardata_t A, it_lineardata_t B ) const;
            void addSubMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11, it_lineardata_t S12, it_lineardata_t T2,
            		       it_lineardata_t S21, it_lineardata_t S22 ) const;
            void subMatricesCAPS( int numEntries, it_lineardata_t C, it_lineardata_t A, it_lineardata_t B ) const;
            void tripleAddMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11, it_lineardata_t S12, it_lineardata_t T2,
            		       it_lineardata_t S21, it_lineardata_t S22, it_lineardata_t T3, it_lineardata_t S31, it_lineardata_t S32) const;
            void tripleSubMatricesCAPS(int numEntries, it_lineardata_t T1, it_lineardata_t S11, it_lineardata_t S12, it_lineardata_t T2,
            		       it_lineardata_t S21, it_lineardata_t S22, it_lineardata_t T3, it_lineardata_t S31, it_lineardata_t S32) const ;


            void distributeFrom1ProcCAPS( MatDescriptor desc, it_lineardata_t O, it_lineardata_t I ) const;
            void collectTo1ProcCAPS( MatDescriptor desc, it_lineardata_t O, it_lineardata_t I ) const;
            void sendBlockCAPS( int rank, int target, it_lineardata_t O, int bs, int source, it_lineardata_t I, int ldi ) const;
            void receiveBlockCAPS(  int rank, int target, it_lineardata_t O, int bs, int source, it_lineardata_t I, int ldo ) const;
            void distributeFrom1ProcRecCAPS( MatDescriptor desc, it_lineardata_t O, it_lineardata_t I, int ldi ) const;
            void collectTo1ProcRecCAPS( MatDescriptor desc, it_lineardata_t O, it_lineardata_t I, int ldo ) const;

            void testCAPS( MatDescriptor desc );
		};




	/**
    * Operator for scalar multiplication of matrix
	*
	* @param &e element
	* @param &M matrix
	* @return the resulting matrix
    */ 
    template<class Element>
    inline Matrix<Element> operator*(Element const& e, Matrix<Element> const& M) {
        return M.ScalarMult(e);
    }

	/**
    * Generates a matrix of rotations. See pages 7-8 of https://eprint.iacr.org/2013/297
	*
	* @param &inMat the matrix of power-of-2 cyclotomic ring elements to be rotated
	* @return the resulting matrix of big binary integers
    */ 
    inline Matrix<BigBinaryInteger> Rotate(Matrix<ILVector2n> const& inMat);

	/**
    *  Each element becomes a square matrix with columns of that element's
    *  rotations in coefficient form. See pages 7-8 of https://eprint.iacr.org/2013/297
	*
	* @param &inMat the matrix of power-of-2 cyclotomic ring elements to be rotated
	* @return the resulting matrix of big binary integers
    */ 
    inline Matrix<BigBinaryVector> RotateVecResult(Matrix<ILVector2n> const& inMat);

	/**
    *  Stream output operator
	*
	* @param &os stream
	* @param &m matrix to be outputted
	* @return the chained stream
    */ 
    template<class Element>
    inline std::ostream& operator<<(std::ostream& os, const Matrix<Element>& m);

	/**
    * Gives the Choleshky decomposition of the input matrix. 
	* The assumption is that covariance matrix does not have large coefficients because it is formed by
    * discrete gaussians e and s; this implies int32_t can be used
    * This algorithm can be further improved - see the Darmstadt paper section 4.4
	*  http://eprint.iacr.org/2013/297.pdf
	*
	* @param &input the matrix for which the Cholesky decomposition is to be computed
	* @return the resulting matrix of floating-point numbers
    */ 
    inline Matrix<LargeFloat> Cholesky(const Matrix<int32_t> &input); 

	/**
    * Convert a matrix of integers from BigBinaryInteger to int32_t
	* Convert from Z_q to [-q/2, q/2]
	*
	* @param &input the input matrix
	* @param &modulus the ring modulus
	* @return the resulting matrix of int32_t
    */ 
    inline Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryInteger> &input, const BigBinaryInteger& modulus);

	/**
    * Convert a matrix of BigBinaryVector to int32_t
	* Convert from Z_q to [-q/2, q/2]
	*
	* @param &input the input matrix
	* @param &modulus the ring modulus
	* @return the resulting matrix of int32_t
    */ 
    inline Matrix<int32_t> ConvertToInt32(const Matrix<BigBinaryVector> &input, const BigBinaryInteger& modulus); 

	/**
    * Split a vector of int32_t into a vector of ring elements with ring dimension n
	*
	* @param &other the input matrix
	* @param &n the ring dimension
	* @param &params ILVector2n element params
	* @return the resulting matrix of ILVector2n
    */ 
    inline Matrix<ILVector2n> SplitInt32IntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const shared_ptr<ILParams> params);

	/**
    * Another method for splitting a vector of int32_t into a vector of ring elements with ring dimension n
	*
	* @param &other the input matrix
	* @param &n the ring dimension
	* @param &params ILVector2n element params
	* @return the resulting matrix of ILVector2n
    */ 
    inline Matrix<ILVector2n> SplitInt32AltIntoILVector2nElements(Matrix<int32_t> const& other, size_t n, const shared_ptr<ILParams> params);

}
#endif // LBCRYPTO_MATH_MATRIX_H
