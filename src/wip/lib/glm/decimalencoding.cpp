/**
 * @file decimalencoding.cpp Represents and defines plaintext encodings in Palisade with bit packing capabilities.
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
#include "decimalencoding.h"


namespace lbcrypto
{

void DecimalEncoding::CRT(const Matrix<BigInteger>& inMat, vector<Matrix<BigInteger>>& outMat){

	for(size_t k=0; k<modList.size(); k++)
		for(size_t i=0; i<inMat.GetCols(); i++)
			for(size_t j=0; j<inMat.GetRows(); j++)
				outMat[k](j, i) = inMat(j, i)%BigInteger(modList[k]);
}

void DecimalEncoding::ConvertToDouble(const Matrix<BigInteger>& inMat, vector<vector<double>>& outVector){

	if(outVector.size() == 0)
		throw std::logic_error("Input data column size cannot be 0");
	else{
		if(outVector[0].size() == 0)
			throw std::logic_error("Input data row size cannot be 0");

		for(size_t i=0; i<outVector[0].size(); i++)
			if(outVector[0].size() != outVector[i].size())
				throw std::logic_error("Input data row size does not match");
	}

    if (outVector.size() != inMat.GetCols() || outVector[0].size() != inMat.GetRows()) {
        throw invalid_argument("Matrix and vector have incompatible dimensions");
    }

	for(uint64_t i=0; i<inMat.GetRows(); i++)
		for(uint64_t j=0; j<inMat.GetCols(); j++)
			outVector[j][i] = inMat(i, j).ConvertToDouble();
}

void DecimalEncoding::ConvertToDouble(const Matrix<BigInteger>& inMat, Matrix<double>& outMat){

    if (outMat.GetCols() != inMat.GetCols() || outMat.GetRows() != inMat.GetRows()) {
        throw invalid_argument("Matrix and vector have incompatible dimensions");
    }

	for(uint64_t i=0; i<inMat.GetRows(); i++)
		for(uint64_t j=0; j<inMat.GetCols(); j++)
			outMat(i, j) = inMat(i, j).ConvertToDouble();
}

void DecimalEncoding::ConvertToBigInteger(const vector<vector<double>>& inVec, Matrix<BigInteger>& outMat){

	if(inVec.size() == 0)
		throw std::logic_error("Input data column size cannot be 0");
	else{
		if(inVec[0].size() == 0)
			throw std::logic_error("Input data row size cannot be 0");

		for(size_t i=0; i<inVec[0].size(); i++)
			if(inVec[0].size() != inVec[i].size())
				throw std::logic_error("Input data row size does not match");
	}

    if (inVec.size() != outMat.GetCols() || inVec[0].size() != outMat.GetRows()) {
        throw invalid_argument("Matrix and vector have incompatible dimensions");
    }

	size_t dataRowSize = inVec.size();
	size_t dataColSize = inVec[0].size();

	for(size_t i=0; i<dataColSize; i++)
			for(size_t j=0; j<dataRowSize; j++)
				outMat(j, i) = BigInteger(std::llround(inVec[i][j]));
}

void DecimalEncoding::ConvertToBigInteger(const Matrix<double>& inMat, Matrix<BigInteger>& outMat){

    if (inMat.GetCols() != outMat.GetCols() || inMat.GetRows() != outMat.GetRows()) {
        throw invalid_argument("Matrix and vector have incompatible dimensions");
    }

	size_t dataRowSize = inMat.GetRows();
	size_t dataColSize = inMat.GetCols();

	for(size_t i=0; i<dataColSize; i++)
			for(size_t j=0; j<dataRowSize; j++)
				outMat(j, i) = BigInteger(std::llround(inMat(j, i)));
}

void DecimalEncoding::CRTInterpolate(const vector<Matrix<BigInteger>> &crtVector, Matrix<BigInteger> &inMat) {

   	BigInteger Q(1);
   	BigInteger temp;
   	vector<BigInteger> q;

   	for(size_t i=0; i<modList.size(); i++){
   		temp.SetValue(modList[i].ToString());
   		q.push_back(temp);
   		Q = Q*temp;
   	}

	vector<BigInteger> qInverse;

	for (size_t i = 0; i < crtVector.size(); i++)
		qInverse.push_back((Q/q[i]).ModInverse(q[i]));

	for (size_t k = 0; k < inMat.GetRows(); k++){
		for (size_t j = 0; j < inMat.GetCols(); j++){
			BigInteger value = 0;
			for (size_t i = 0; i < crtVector.size(); i++) {
				value += ((BigInteger(crtVector[i](k, j))*qInverse[i]).Mod(q[i])*(Q/q[i])).Mod(Q);
			}
			value = value.Mod(Q);
			inMat(k, j).SetValue(value.ToString());
		}
	}

}

double DecimalEncoding::GetMax(const vector<vector<double>> &data){

		double max = data[0][0];

		for(size_t i=0; i<data.size(); i++)
			for(size_t j=0; j<data[0].size(); j++)
				if(data[i][j]>max)
					max = data[i][j];

		return max;
}

}
