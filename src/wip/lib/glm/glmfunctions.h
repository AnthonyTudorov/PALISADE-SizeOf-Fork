/**
 * @file glmfunctions.h Represents and defines generalized linear method in Palisade with regression capabilities.
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

#ifndef SRC_WRAPPERS_PYTHON_GLMFUNCTIONS_H_
#define SRC_WRAPPERS_PYTHON_GLMFUNCTIONS_H_

#include <iostream>
#include <fstream>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/encodings.h"
#include "decimalencoding.h"

#include "../demo/Temp-matrixinverse.h"

#include "utils/debug.h"
#include <random>
#include <math.h>
#include "math/nbtheory.h"
#include "math/matrix.h"
#include "math/matrix.cpp"

using namespace std;
using namespace lbcrypto;

#include <iterator>
#include <math.h>

//#define MEASURE_TIMING
//#define OMPSECTION3
//#define NUMTHREAD 8

#ifdef MEASURE_TIMING
struct timingParams{
	vector<double> read		= {0.0, 0.0, 0.0};
	vector<double> write 	= {0.0, 0.0, 0.0};
	vector<double> process	= {0.0, 0.0, 0.0};
};
#endif

struct glmParams{
	uint64_t MAXVALUE;
	uint64_t PRECISION;
	uint64_t PRECISIONDECIMALSIZE;
	uint64_t PRECISIONDECIMALSIZEX;

	uint64_t PLAINTEXTPRIMESIZE;
	uint64_t PLAINTEXTBITSIZE;

	uint64_t REGRLOOPCOUNT;

	uint64_t NUMTHREADS;
};

/////////////////////////////////////////////////////////////////////////
/////////                     SERVER                            /////////
/////////////////////////////////////////////////////////////////////////

void GLMServerXW(string keyDir,
				string keyfileName,
				string ciphertextDataDir,
				string ciphertextDataFileName,
				string ciphertextXFileName,
				string ciphertextWFileName,
				string ciphertextResultFileName,
				glmParams & params);

void GLMServerXTSX(string keyDir,
					string keyfileName,
					string ciphertextDataDir,
					string ciphertextDataFileName,
					string ciphertextSFileName,
					string ciphertextXFileName,
					string ciphertextC1FileName,
					glmParams & params);

void GLMServerComputeRegressor(string keyDir,
				   string keyfileName,
				   string ciphertextDataDir,
				   string ciphertextDataFileName,
				   string ciphertextWFileName,
				   string ciphertextXFileName,
				   string ciphertextYFileName,
				   string ciphertextMUFileName,
				   string ciphertextC1FileName,
				   string ciphertextC1C2FileName,
				   glmParams & params);

/////////////////////////////////////////////////////////////////////////
/////////                     CLIENT                            /////////
/////////////////////////////////////////////////////////////////////////

void GLMKeyGen(string keyDir, string keyfileName, glmParams &params);

void GLMEncrypt(string keyDir,
             string keyfileName,
             string plaintextDataDir,
             string plaintextDataFileName,
             string ciphertextDataDir,
             string ciphertextDataFileName,
			 string ciphertextXFileName,
			 string ciphertextYFileName,
			 string ciphertextWFileName,

			 glmParams &params);

void GLMClientLink(string keyDir,
				   string keyfileName,
				   string ciphertextDataDir,
				   string ciphertextDataFileName,
				   string ciphertextMUFileName,
				   string ciphertextSFileName,
				   string ciphertextXWFileName,
				   string ciphertextYFileName,
				   string regAlgorithm,
				   glmParams & params);

void GLMClientRescaleC1(string keyDir,
		 	 	 	 string keyfileName,
					 string ciphertextDataDir,
					 string ciphertextDataFileName,
					 string ciphertextC1FileName,
					 glmParams & params);

vector<double> GLMClientRescaleRegressor(string keyDir,
				   string keyfileName,
				   string ciphertextDataDir,
				   string ciphertextDataFileName,
				   string ciphertextC1C2FileName,
				   string ciphertextWFileName,
				   glmParams & params);

double GLMClientComputeError(string keyDir, string keyfileName, string ciphertextDataDir, string ciphertextDataFileName,
		string ciphertextMUFileName, string ciphertextYFileName, glmParams & params);

#ifdef MEASURE_TIMING
void GLMPrintTimings(string sel);
#endif

/////////////////////////////////////////////////////////////////////////
/////////                     GENERATORS                        /////////
/////////////////////////////////////////////////////////////////////////
void MessagePrimeListGen(vector<NativeInteger> &primeList, usint &m, glmParams & params);
//shared_ptr<ILDCRTParams<BigInteger>> CiphertextDCRTParamGen(NativeInteger &prime, glmParams & params);
EncodingParams PlaintextEncodingParamGen(NativeInteger &prime, usint &m, glmParams & params);

/////////////////////////////////////////////////////////////////////////
/////////                     READ/WRITE                        /////////
/////////////////////////////////////////////////////////////////////////
void ReadCSVFile(string dataFileName, vector<string>& headers, vector<vector<double> >& dataColumns);
void ReadMetaData(string ciphertextDataDir, string ciphertextDataFileName, size_t &numCol, size_t &numRow);
void WriteMetaData(const string &metaDataPath, const vector<string> &headers, const vector<vector<double>> &dataColumns);
void WritePlaintextSpacePrimes(string dataDir, string dataFileName, const vector<NativeInteger> &primeList);
void ReadPlaintextSpacePrimes(string dataDir, string dataFileName, vector<BigInteger> &primeList);
void ParseData(vector<vector<double>> &dataColumns, vector<vector<double>> &xPDouble, vector<vector<double>> &yPDouble);

/////////////////////////////////////////////////////////////////////////
/////////                     Deserialize/Serialize             /////////
/////////////////////////////////////////////////////////////////////////
CryptoContext<DCRTPoly> DeserializeContext(const string& ccFileName);
LPPublicKey<DCRTPoly> DeserializePublicKey(CryptoContext<DCRTPoly> &cc, const string& pkFileName);
LPPrivateKey<DCRTPoly> DeserializePrivateKey(CryptoContext<DCRTPoly> &cc, const string& pkFileName);
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> DeserializeCiphertext(CryptoContext<DCRTPoly> &cc, const string &path);
void DeserializeEvalMult(CryptoContext<DCRTPoly> &cc, const string& emFileName);
void DeserializeEvalSum(CryptoContext<DCRTPoly> &cc, const string& esFileName);
void SerializeContext(CryptoContext<DCRTPoly> &cc, const string &xFileName);
void SerializePublicKey(LPPublicKey<DCRTPoly> &C, const string &xFileName);
void SerializePrivateKey(LPPrivateKey<DCRTPoly> &C, const string &xFileName);
void SerializeCiphertext(shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C, const string &xFileName);
void SerializeMultEvalKey(CryptoContext<DCRTPoly> &cc, const vector<LPEvalKey<DCRTPoly>> &evalMultKey, const string &xFileName);
void SerializeSumEvalKey(CryptoContext<DCRTPoly> &cc, const std::map<usint, LPEvalKey<DCRTPoly>>& evalSumKey, const string &xFileName);

/////////////////////////////////////////////////////////////////////////
/////////                     Arithmetic Functions              /////////
/////////////////////////////////////////////////////////////////////////
double ComputeError(Matrix<BigInteger> &mu, Matrix<BigInteger> &y, size_t size, glmParams &params);
void LinkFunctionLogisticSigned(vector<CryptoContext<DCRTPoly>> &cc, const Matrix<BigInteger> &wTb, vector<shared_ptr<Matrix<Plaintext>>> &mu,
								vector<shared_ptr<Matrix<Plaintext>>> &S, const size_t dataEntrySize,
								const vector<NativeInteger> &primeList, string regAlgorithm, glmParams &params);

shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyWTransX(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &beta);
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXTransX(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x);
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXTransS(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &SC);
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXTransSX(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C0);
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyXAddYMu(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &y, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &x, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &muC);
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyC0C1(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C0, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C1);
shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> MultiplyC0C1C2(CryptoContext<DCRTPoly> &cc, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C0C1, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> &C2);

/////////////////////////////////////////////////////////////////////////
/////////                     CRT/Encoding Functions            /////////
/////////////////////////////////////////////////////////////////////////
void CRTInterpolateMatrix(const vector<Matrix<Plaintext>> &crtVector, Matrix<BigInteger> &result, const vector<NativeInteger> &primeList, glmParams &params);
void CRTInterpolateMatrixEntrySelect(const vector<Matrix<Plaintext>> &crtVector, Matrix<BigInteger> &result, const vector<NativeInteger> &primeList, const size_t &colIndex);
void CRTInterpolate(const std::vector<Matrix<Plaintext>> &crtVector, Matrix<BigInteger> &result, const vector<NativeInteger> &primeList);
void DiagMatrixInverse(const vector<double> &in, vector<double> &out);
void ConvertUnsingedToSigned(const Matrix<BigInteger> &in, Matrix<double> &out, vector<NativeInteger> &primeList);
void MatrixInverse(const Matrix<BigInteger>& in, Matrix<double>& out);//, uint32_t numRegressors);
void MatrixInverse(const Matrix<double>& in, Matrix<double>& out);//, uint32_t numRegressors);

void ConvertMatrixBigIntegerToPlaintextEncoding(const CryptoContext<DCRTPoly> &cc, const Matrix<BigInteger> &inMat, Matrix<Plaintext> &outMat);
void ConvertPlaintextEncodingToMatrixBigInteger(const CryptoContext<DCRTPoly> &cc, const Matrix<Plaintext> &inMat, Matrix<BigInteger> &outMat, glmParams &params);

void DataToCRT(vector<vector<double>> &xPVecDouble, vector<Matrix<BigInteger>> &xPMatVec, vector<BigInteger> &primeList, uint64_t &decimalInc, glmParams &params);
void EncodeData(CryptoContext<DCRTPoly> &cc, const vector<vector<double> >& dataColumns, Matrix<Plaintext>& x, Matrix<Plaintext>& y, glmParams &params);
void EncodeC0Matrix(vector<CryptoContext<DCRTPoly>> &cc, vector<shared_ptr<Matrix<double>>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize);
void EncodeC1Matrix(vector<CryptoContext<DCRTPoly>> &cc, shared_ptr<Matrix<double>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize);
void EncodeC2Matrix(vector<CryptoContext<DCRTPoly>> &cc, shared_ptr<Matrix<double>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize);
void EncodeC1Matrix(vector<CryptoContext<DCRTPoly>> &cc, shared_ptr<Matrix<BigInteger>> &CList, vector<shared_ptr<Matrix<Plaintext>>> &CP, vector<NativeInteger> &primeList, size_t &batchSize);

/////////////////////////////////////////////////////////////////////////
/////////                     Decimal Scaling Functions         /////////
/////////////////////////////////////////////////////////////////////////
void DecimalIncrement(const Matrix<double> &in, Matrix<double> &out, size_t decimalSize, glmParams &params);
void DecimalDecrement(const Matrix<double> &in, Matrix<double> &out, size_t decimalSize, glmParams &params);
void DecimalIncrement(const double &in, double &out, size_t decimalSize, glmParams &params);
void DecimalDecrement(const double &in, double &out, size_t decimalSize, glmParams &params);
void DecimalIncrement(const vector<shared_ptr<Matrix<double>>> &in, vector<shared_ptr<Matrix<double>>> &out, size_t decimalSize, glmParams &params);
void DecimalDecrement(const vector<shared_ptr<Matrix<double>>> &in, vector<shared_ptr<Matrix<double>>> &out, size_t decimalSize, glmParams &params);

/////////////////////////////////////////////////////////////////////////
/////////                     Printing Functions                /////////
/////////////////////////////////////////////////////////////////////////
void PrintMatrixDouble(const Matrix<double> &in);

/////////////////////////////////////////////////////////////////////////
/////////                     Conversion Functions              /////////
/////////////////////////////////////////////////////////////////////////
void doubleToBigInteger(double &in, BigInteger &out);

#endif /* SRC_WRAPPERS_PYTHON_GLMFUNCTIONS_H_ */




