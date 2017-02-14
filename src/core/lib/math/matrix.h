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
#include "../lattice/ilvectorarray2n.h"
#include "../encoding/intplaintextencoding.h"
#include "../utils/inttypes.h"
#include "../utils/utilities.h"
#include "../utils/memory.h"
using std::invalid_argument;

namespace lbcrypto {

		template<class Element>
        class Matrix : public Serializable {
        public:
            typedef vector<vector<unique_ptr<Element>>> data_t;
            typedef std::function<unique_ptr<Element>(void)> alloc_func;
        

			/**
			 * Constructor that initializes matrix values using a zero allocator
			 *
			 * @param &allocZero lambda function for zero initialization.
			 * @param &rows number of rows.
			 * @param &rows number of columns.
			 */
            Matrix(alloc_func allocZero, size_t rows, size_t cols) : rows(rows), cols(cols), data(), allocZero(allocZero) {
                data.resize(rows);
                for (auto row = data.begin(); row != data.end(); ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        row->push_back(allocZero());
                    }
                }
            }

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
             * Constructor of an empty matrix; SetSize must be called on this matrix to use it
             * Basically this exists to support deserializing
             *
			 * @param &allocZero lambda function for zero initialization.
             */
            Matrix(alloc_func allocZero) : rows(0), cols(0), data(), allocZero(allocZero) {}

            void SetSize(size_t rows, size_t cols) {
            	if( this->rows != 0 || this->cols != 0 )
            		throw std::logic_error("You cannot SetSize on a non-empty matrix");

            	this->rows = rows;
            	this->cols = cols;

                data.resize(rows);
                for (auto row = data.begin(); row != data.end(); ++row) {
                    for (size_t col = 0; col < cols; ++col) {
                        row->push_back(allocZero());
                    }
                }
            }

			/**
			 * Copy constructor
			 *
			 * @param &other the matrix object to be copied
			 */
            Matrix(const Matrix<Element>& other) : data(), rows(other.rows), cols(other.cols), allocZero(other.allocZero) {
                deepCopyData(other.data);
            }

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
            inline Matrix<Element>& Fill(const Element &val); 

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
            for (int32_t col = 0; col < result.cols; ++col) {
            	for (int32_t row = 0; row < result.rows; ++row) {

                        *result.data[row][col] = *result.data[row][col] * other;
                    }
                }

            #endif
                return result;
            }

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
            for (int32_t j = 0; j < cols; ++j) {
            for (int32_t i = 0; i < rows; ++i) {
                        *result.data[i][j] += *other.data[i][j];
                    }
                }
            #endif
                return result;
            }


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
            for (int32_t j = 0; j < cols; ++j) {
            	for (int32_t i = 0; i < rows; ++i) {
                        *result.data[i][j] = *data[i][j] - *other.data[i][j];
                    }
                }
            #endif

                return result;
            }

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

			// YSP The signature of this method needs to be changed in the future
			/**
			* Matrix determinant - found using Laplace formula with complexity O(d!), where d is the dimension
			*
			* @param *result where the result is stored
			*/
			inline void Determinant(Element *result) const;
			//inline Element Determinant() const;

			/**
			* Cofactor matrix - the matrix of determinants of the minors A_{ij} multiplied by -1^{i+j}
			*
			* @return the cofactor matrix for the given matrix
			*/
			inline Matrix<Element> CofactorMatrix() const;

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
			* Matrix row extractor
			*
			* @param &row row index
			* @return the row at the index
			*/
			inline Matrix<Element> ExtractRow(size_t row) const {
				Matrix<Element> result(this->allocZero,1,this->cols);
				int i = 0;
				for (auto elem = this->GetData()[row].begin(); elem != this->GetData()[row].end(); ++elem) {
					result(0,i) = **elem;
					i++;
				}
				return result;
				//return *this;
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


            /*
             * Multiply the matrix by a vector whose elements are all 1's.  This causes the elements of each
             * row of the matrix to be added and placed into the corresponding position in the output vector.
             */
            Matrix<Element> MultByUnityVector() const;

            /*
             * Multiply the matrix by a vector of random 1's and 0's, which is the same as adding select
             * elements in each row together.
             * Return a vector that is a rows x 1 matrix.
             */
            Matrix<Element> MultByRandomVector(std::vector<int> ranvec) const;

			/**
			* Serialize the object into a Serialized
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj) const;

			/**
			* Populate the object from the deserialization of the Serialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj);


        private:
            data_t data;
            size_t rows;
            size_t cols;
            alloc_func allocZero;
            //mutable int NUM_THREADS = 1;

			//deep copy of data - used for copy constructor
            void deepCopyData(data_t const& src);

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
