/**
 * @file decimalencoding.h Represents and defines plaintext encodings in Palisade with bit packing capabilities.
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

#ifndef SRC_CORE_LIB_ENCODING_DECIMALENCODING_H_
#define SRC_CORE_LIB_ENCODING_DECIMALENCODING_H_


#include "inttypes.h"
#include <vector>
#include <initializer_list>
#include "encoding/plaintext.h"
#include "encoding/encodingparams.h"
#include <functional>
#include <numeric>

#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

namespace lbcrypto
{

class DecimalEncoding
{

public:
	//Construction
	DecimalEncoding(vector<BigInteger> &modArray, uint64_t prec){
		this->prec = prec;

		for(size_t i=0; i<modArray.size(); i++)
			modList.push_back(modArray[i]);
	}

	/**
	 * Method to increment the decimal of the entries of the input matrix.
	 * @param inMat - the input matrix that it's entries will be incremented
	 * @param outMat - the output matrix that it's entries will be incremented
	 * @param decimalSize - number of decimals to increase
	 */
	template<typename intType>
	void DecimalIncrement(const Matrix<intType>& inMat, Matrix<intType>& outMat, const uint64_t decimalSize){
		double decimal = prec;
		for(uint64_t i=1; i<decimalSize; i++)
			decimal = decimal*prec;

		for(uint64_t i=0; i<inMat.GetRows(); i++)
			for(uint64_t j=0; j<inMat.GetCols(); j++)
				outMat(i, j) = inMat(i, j)*decimal;
	}

	/**
	 * Method to decrement the decimal of the entries of the input matrix.
	 * @param inMat - the input matrix that it's entries will be decremented
	 * @param outMat - the output matrix that it's entries will be decremented
	 * @param decimalSize - number of decimals to decrease
	 */
	template<typename intType>
	void DecimalDecrement(const Matrix<intType>& inMat, Matrix<intType>& outMat, const uint64_t decimalSize){
		double decimal = prec;
		for(uint64_t i=1; i<decimalSize; i++)
			decimal = decimal*prec;

		for(uint64_t i=0; i<inMat.GetRows(); i++)
			for(uint64_t j=0; j<inMat.GetCols(); j++)
				outMat(i, j) = inMat(i, j)/decimal;
	}

	/**
	 * Method to convert the matrix entries into a vector matrix with smaller entries with modular modList used.
	 * @param inMat - the input matrix that it's entries will be reduced into smaller ones with the modList
	 * @param outMat - the output matrix list that their entries are reduced into smaller ones with the modList
	 */
	void CRT(const Matrix<BigInteger>& inMat, vector<Matrix<BigInteger>>& outMat);

	/**
	 * Method to calculate the real entry values of the matrix using CRT interpolation
	 * @param inMat - the input matrix list to rebuilt the numbers using the CRT entries of the input matrix
	 * @param outMat - the output matrix which the CRT Interpolation is calculated
	 */
	void CRTInterpolate(const vector<Matrix<BigInteger>> &inMat, Matrix<BigInteger> &outMat);

	/**
	 * Method to convert type of the matrix entries from double to BigInteger
	 * @param inMat - the input matrix that it's entries will be converted to the BigInteger type
	 * @param outMat - the output matrix with BigInteger type
	 */
	void ConvertToBigInteger(const vector<vector<double>>& inVec, Matrix<BigInteger>& outMat);

	/**
	 * Method to convert type of the matrix entries from double to BigInteger
	 * @param inMat - the input matrix that it's entries will be converted to the BigInteger type
	 * @param outMat - the output matrix with BigInteger type
	 */
	void ConvertToBigInteger(const Matrix<double>& inMat, Matrix<BigInteger>& outMat);

	/**
	 * Method to convert type of the matrix entries from BigInteger to double.
	 * @param inMat - the input matrix that it's entries will be converted to double
	 * @param outMat - the output matrix that it's entries converted to double
	 */
	void ConvertToDouble(const Matrix<BigInteger>& inMat, vector<vector<double>>& outVec);

	/**
	 * Method to convert type of the matrix entries from BigInteger to double.
	 * @param inMat - the input matrix that it's entries will be converted to double
	 * @param outMat - the output matrix that it's entries converted to double
	 */
	void ConvertToDouble(const Matrix<BigInteger>& inMat, Matrix<double>& outMat);

	/**
	 * Method to convert type of the matrix entries from BigInteger to double.
	 * @param inMat - the input matrix that it's entries will be converted to double
	 * @param outMat - the output matrix that it's entries converted to double
	 */
	template<typename intType>
	void ConvertVectorToMatrix(const vector<vector<intType>>& inVec, Matrix<intType>& outMat){

	    if (inVec.size() != outMat.GetCols() || inVec[0].size() != outMat.GetRows()) {
	        throw invalid_argument("Matrix and vector have incompatible dimensions");
	    }

		for(size_t i=0; i<inVec.size(); i++)
			for(size_t j=0; j<inVec[i].size(); j++)
				outMat(j, i) = inVec[i][j];
	}

private:

	uint64_t prec;
	vector<BigInteger> modList;
	/**
	 * Method to find the largest element in the matrix
	 * @param data - the input matrix
	 * @return largest element in the matrix
	 */
	double GetMax(const vector<vector<double>> &data);

};

}



#endif /* SRC_CORE_LIB_ENCODING_DECIMALENCODING_H_ */
