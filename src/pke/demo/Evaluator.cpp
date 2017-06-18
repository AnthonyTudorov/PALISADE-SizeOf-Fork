/*
 * @file 
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

#include <iostream>
#include <fstream>

#include "math/matrix.h"
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

//using namespace std;
using namespace lbcrypto;
void EvalLinRegressionNull();
void EvalLinRegressionNull3();
void EvalLinRegressionFV();
void EvalLinRegressionFV3();
void RationalTests();
void IntegerTests();
//double currentDateTime();


#include <iterator>

int main() {

	std::cout << "====================================================== " << std::endl;
	std::cout << "STARTING NULL SCHEME EXPERIMENTS FOR 2 REGRESSORS " << std::endl;
	EvalLinRegressionNull();
	std::cout << "ENDED NULL SCHEME EXPERIMENTS " << std::endl;
	std::cout << "====================================================== " << std::endl;

	std::cout << "\n====================================================== " << std::endl;
	std::cout << "STARTING NULL SCHEME EXPERIMENTS FOR 3 REGRESSORS " << std::endl;
	EvalLinRegressionNull3();
	std::cout << "ENDED NULL SCHEME EXPERIMENTS " << std::endl;
	std::cout << "====================================================== " << std::endl;

	std::cout << "\n====================================================== " << std::endl;
	std::cout << "STARTING FV SCHEME EXPERIMENTS FOR 2 REGRESSORS" << std::endl;
	EvalLinRegressionFV();
	std::cout << "ENDED FV SCHEME EXPERIMENTS " << std::endl;
	std::cout << "====================================================== " << std::endl;
	//RationalTests();

	std::cout << "\n====================================================== " << std::endl;
	std::cout << "STARTING FV SCHEME EXPERIMENTS FOR 3 REGRESSORS " << std::endl;
	EvalLinRegressionFV3();
	std::cout << "ENDED FV SCHEME EXPERIMENTS " << std::endl;
	std::cout << "====================================================== " << std::endl;

	std::cin.get();

	return 0;
}

void EvalLinRegressionNull() {

	//usint relWindow = 8;

	usint plaintextModulus = 256;
	usint m = 64;
	ILVector2n::Integer modulus("256");
	ILVector2n::Integer rootOfUnity("268585022");

	shared_ptr<ILVector2n::Params> ep(new ILVector2n::Params(m, modulus, rootOfUnity));
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextNull(ep, plaintextModulus);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	std::cout << "RationalCiphertext s/d test" << std::endl;
	Ciphertext<ILVector2n> one(cc), two(cc), three(cc);
	ILVector2n onevec(cc.GetElementParams()), twovec(cc.GetElementParams()), threevec(cc.GetElementParams());
	onevec = { 1 };
	twovec = { 2 };
	threevec = { 3 };
	one.SetElement(onevec);
	two.SetElement(twovec);
	three.SetElement(threevec);
	RationalCiphertext<ILVector2n> aninteger(three);
	RationalCiphertext<ILVector2n> areal(one, two);

	Serialized rc;
	std::cout << "Integer: " << std::flush;
	if( aninteger.Serialize(&rc) ) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if( newOne.Deserialize(rc) ) {
			std::cout << "Deserialized! " << (aninteger == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Serialized rc2;
	std::cout << "Real: " << std::flush;
	if( areal.Serialize(&rc2) ) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if( newOne.Deserialize(rc2) ) {
			std::cout << "Deserialized! " << (areal == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Matrix<RationalCiphertext<ILVector2n>> mmm([cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); } );
	Serialized mmmS;
	if( SerializableHelper::ReadSerializationFromFile("matrix.json", &mmmS) ) {
		std::cout << "Trying to deserialize file" << std::endl;
		if( mmm.Deserialize(mmmS) ) {
			std::cout << "Deserialized matrix" << std::endl;
		} else {
			std::cout << "r,c is" << mmm.GetRows() << "," << mmm.GetCols() << std::endl;
			const Matrix<RationalCiphertext<ILVector2n>>::data_t& e = mmm.GetData();
			std::cout << e.size() << std::endl;
			for( size_t i=0; i<e.size(); i++ )
				std::cout << i << ":" << e.at(i).size() << std::endl;
		}
	}

	double diff, start, finish;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;
	
	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 2);

	xP(0, 0) = 173;
	xP(0, 1) = 107;
	xP(1, 0) = 175;
	xP(1, 1) = 105;

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = 167;
	yP(1, 0) = 105;
	
	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	std::cout << "Key generation started" << std::endl;

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	cc.EvalMultKeyGen(kp.secretKey);

	std::cout << "Key generation ended" << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Encryption execution time for the x matrix: " << "\t" << diff << " ms" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	std::cout << "MATRIX: " << y->GetRows() << "," << y->GetCols() << std::endl;

	Serialized rcm;
	Matrix<RationalCiphertext<ILVector2n>> newMat( [cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); } );
	if( y->Serialize(&rcm) ) {
		std::cout << "Matrix serialized" << std::endl;
//		SerializableHelper::SerializationToStream(rcm, std::cout);
//		std::cout << std::endl;

		if( newMat.Deserialize(rcm) ) {
			std::cout << "Matrix deserialized" << std::endl;

			if( y->GetRows() != newMat.GetRows() ) {
				std::cout << "row # mismatch" << std::endl;
			}
			if( y->GetCols() != newMat.GetCols() ) {
				std::cout << "col # mismatch" << std::endl;
			}

			for( size_t r=0; r<y->GetRows(); r++ ) {
				for( size_t c=0; c<y->GetCols(); c++ ) {
					if( (*y)(r,c) != newMat(r,c) ) {
						std::cout << "element mismatch at " << r << "," << c << std::endl;
					}
				}
			}

			std::cout << "DONE CHECKING" << std::endl;
		}
	}

	//code for testing the deserialization of the first argument

	Serialized ser;
	(void)x->Serialize(&ser);
	auto alloc = [=]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); };
	auto c1_ = std::make_shared<Matrix<RationalCiphertext<ILVector2n>>>(alloc);
	(void)c1_->Deserialize(ser);

	auto result3 = cc.EvalLinRegression(c1_, y);

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc.EvalLinRegression(x, y);
	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << result->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << result->GetCols() << std::endl;

	auto deserResult = cc.EvalLinRegression(x, std::make_shared<Matrix<RationalCiphertext<ILVector2n>>>(newMat));
	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << deserResult->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << deserResult->GetCols() << std::endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<IntPlaintextEncoding> numerator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<IntPlaintextEncoding> denominator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc.DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << "numerator row 1 = " << numerator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator(1, 0).EvalToInt(plaintextModulus) << std::endl;

	std::cout << "on deserialized" << std::endl;
	Matrix<IntPlaintextEncoding> numerator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<IntPlaintextEncoding> denominator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc.DecryptMatrix(kp.secretKey, deserResult, &numerator2, &denominator2);

	std::cout << "numerator row 1 = " << numerator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator2(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator2(1, 0).EvalToInt(plaintextModulus) << std::endl;


}

void EvalLinRegressionNull3() {

	//usint relWindow = 8;

	usint plaintextModulus = 256;
	usint m = 64;
	ILVector2n::Integer modulus("256");
	ILVector2n::Integer rootOfUnity("268585022");

	shared_ptr<ILVector2n::Params> ep(new ILVector2n::Params(m, modulus, rootOfUnity));
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextNull(ep, plaintextModulus);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	std::cout << "RationalCiphertext s/d test" << std::endl;
	Ciphertext<ILVector2n> one(cc), two(cc), three(cc);
	ILVector2n onevec(cc.GetElementParams()), twovec(cc.GetElementParams()), threevec(cc.GetElementParams());
	onevec = { 1 };
	twovec = { 2 };
	threevec = { 3 };
	one.SetElement(onevec);
	two.SetElement(twovec);
	three.SetElement(threevec);
	RationalCiphertext<ILVector2n> aninteger(three);
	RationalCiphertext<ILVector2n> areal(one, two);

	Serialized rc;
	std::cout << "Integer: " << std::flush;
	if (aninteger.Serialize(&rc)) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if (newOne.Deserialize(rc)) {
			std::cout << "Deserialized! " << (aninteger == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Serialized rc2;
	std::cout << "Real: " << std::flush;
	if (areal.Serialize(&rc2)) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if (newOne.Deserialize(rc2)) {
			std::cout << "Deserialized! " << (areal == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Matrix<RationalCiphertext<ILVector2n>> mmm([cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); });
	Serialized mmmS;
	if (SerializableHelper::ReadSerializationFromFile("matrix.json", &mmmS)) {
		std::cout << "Trying to deserialize file" << std::endl;
		if (mmm.Deserialize(mmmS)) {
			std::cout << "Deserialized matrix" << std::endl;
		}
		else {
			std::cout << "r,c is" << mmm.GetRows() << "," << mmm.GetCols() << std::endl;
			const Matrix<RationalCiphertext<ILVector2n>>::data_t& e = mmm.GetData();
			std::cout << e.size() << std::endl;
			for (size_t i = 0; i<e.size(); i++)
				std::cout << i << ":" << e.at(i).size() << std::endl;
		}
	}

	double diff, start, finish;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 3);

	for (size_t i = 0; i < 3; ++i) {
		for (size_t j = 0; j < 3; ++j) {
			xP(i, j) = 101%(2*i + j + 1);
		}
	}

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);

	for (size_t i = 0; i < 3; ++i) {
		for (size_t j = 0; j < 1; ++j) {
			yP(i, j) = 99%(2 * i + 5*j + 1);
		}
	}

	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	std::cout << "Key generation started" << std::endl;

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	cc.EvalMultKeyGen(kp.secretKey);

	std::cout << "Key generation ended" << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Encryption execution time for the x matrix: " << "\t" << diff << " ms" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	std::cout << "MATRIX: " << y->GetRows() << "," << y->GetCols() << std::endl;

	Serialized rcm;
	Matrix<RationalCiphertext<ILVector2n>> newMat([cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); });
	if (y->Serialize(&rcm)) {
		std::cout << "Matrix serialized" << std::endl;
		//		SerializableHelper::SerializationToStream(rcm, std::cout);
		//		std::cout << std::endl;

		if (newMat.Deserialize(rcm)) {
			std::cout << "Matrix deserialized" << std::endl;

			if (y->GetRows() != newMat.GetRows()) {
				std::cout << "row # mismatch" << std::endl;
			}
			if (y->GetCols() != newMat.GetCols()) {
				std::cout << "col # mismatch" << std::endl;
			}

			for (size_t r = 0; r<y->GetRows(); r++) {
				for (size_t c = 0; c<y->GetCols(); c++) {
					if ((*y)(r, c) != newMat(r, c)) {
						std::cout << "element mismatch at " << r << "," << c << std::endl;
					}
				}
			}

			std::cout << "DONE CHECKING" << std::endl;
		}
	}

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	auto result = cc.EvalLinRegression(x, y);
	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << result->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << result->GetCols() << std::endl;

	auto deserResult = cc.EvalLinRegression(x, std::make_shared<Matrix<RationalCiphertext<ILVector2n>>>(newMat));
	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << deserResult->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << deserResult->GetCols() << std::endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<IntPlaintextEncoding> numerator = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);
	Matrix<IntPlaintextEncoding> denominator = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);

	cc.DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << "numerator row 1 = " << numerator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 3 = " << numerator(2, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 3 = " << denominator(2, 0).EvalToInt(plaintextModulus) << std::endl;

	std::cout << "on deserialized" << std::endl;
	Matrix<IntPlaintextEncoding> numerator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);
	Matrix<IntPlaintextEncoding> denominator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);

	cc.DecryptMatrix(kp.secretKey, deserResult, &numerator2, &denominator2);

	std::cout << "numerator row 1 = " << numerator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator2(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 3 = " << numerator2(2, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator2(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 3 = " << denominator2(2, 0).EvalToInt(plaintextModulus) << std::endl;

}

void EvalLinRegressionFV() {

	usint plaintextModulus = 256;
	usint relWindow = 16;
	float stdDev = 4;

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(plaintextModulus, 1.006, relWindow, stdDev, 0, 3, 0);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	std::cout << "RationalCiphertext s/d test" << std::endl;
	Ciphertext<ILVector2n> one(cc), two(cc), three(cc);
	ILVector2n onevec(cc.GetElementParams()), twovec(cc.GetElementParams()), threevec(cc.GetElementParams());
	onevec = { 1 };
	twovec = { 2 };
	threevec = { 3 };
	one.SetElement(onevec);
	two.SetElement(twovec);
	three.SetElement(threevec);
	RationalCiphertext<ILVector2n> aninteger(three);
	RationalCiphertext<ILVector2n> areal(one, two);

	Serialized rc;
	std::cout << "Integer: " << std::flush;
	if (aninteger.Serialize(&rc)) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if (newOne.Deserialize(rc)) {
			std::cout << "Deserialized! " << (aninteger == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Serialized rc2;
	std::cout << "Real: " << std::flush;
	if (areal.Serialize(&rc2)) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if (newOne.Deserialize(rc2)) {
			std::cout << "Deserialized! " << (areal == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Matrix<RationalCiphertext<ILVector2n>> mmm([cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); });
	Serialized mmmS;
	if (SerializableHelper::ReadSerializationFromFile("matrix.json", &mmmS)) {
		std::cout << "Trying to deserialize file" << std::endl;
		if (mmm.Deserialize(mmmS)) {
			std::cout << "Deserialized matrix" << std::endl;
		}
		else {
			std::cout << "r,c is" << mmm.GetRows() << "," << mmm.GetCols() << std::endl;
			const Matrix<RationalCiphertext<ILVector2n>>::data_t& e = mmm.GetData();
			std::cout << e.size() << std::endl;
			for (size_t i = 0; i<e.size(); i++)
				std::cout << i << ":" << e.at(i).size() << std::endl;
		}
	}

	double diff, start, finish;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 2);

	xP(0, 0) = 173;
	xP(0, 1) = 107;
	xP(1, 0) = 175;
	xP(1, 1) = 105;

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	yP(0, 0) = 167;
	yP(1, 0) = 105;


	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	std::cout << "Key generation started" << std::endl;

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	cc.EvalMultKeyGen(kp.secretKey);

	std::cout << "Key generation ended" << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Encryption execution time for the x matrix: " << "\t" << diff << " ms" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	std::cout << "MATRIX: " << y->GetRows() << "," << y->GetCols() << std::endl;

	Serialized rcm;
	Matrix<RationalCiphertext<ILVector2n>> newMat([cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); });
	if (y->Serialize(&rcm)) {
		std::cout << "Matrix serialized" << std::endl;
		//		SerializableHelper::SerializationToStream(rcm, std::cout);
		//		std::cout << std::endl;

		if (newMat.Deserialize(rcm)) {
			std::cout << "Matrix deserialized" << std::endl;

			if (y->GetRows() != newMat.GetRows()) {
				std::cout << "row # mismatch" << std::endl;
			}
			if (y->GetCols() != newMat.GetCols()) {
				std::cout << "col # mismatch" << std::endl;
			}

			for (size_t r = 0; r<y->GetRows(); r++) {
				for (size_t c = 0; c<y->GetCols(); c++) {
					if ((*y)(r, c) != newMat(r, c)) {
						std::cout << "element mismatch at " << r << "," << c << std::endl;
					}
				}
			}

			std::cout << "DONE CHECKING" << std::endl;
		}
	}

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	std::cout << "\nComputing linear regression... "  << std::endl;

	start = currentDateTime();

	auto result = cc.EvalLinRegression(x, y);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Linear regression execution time: " << "\t" << diff << " ms\n" << std::endl;

	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << result->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << result->GetCols() << std::endl;

	std::cout << "\nComputing linear regression from deserialized data... " << std::endl;

	auto deserResult = cc.EvalLinRegression(x, std::make_shared<Matrix<RationalCiphertext<ILVector2n>>>(newMat));
	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << deserResult->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << deserResult->GetCols() << std::endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<IntPlaintextEncoding> numerator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<IntPlaintextEncoding> denominator = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc.DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << "numerator row 1 = " << numerator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator(1, 0).EvalToInt(plaintextModulus) << std::endl;

	std::cout << "on deserialized" << std::endl;
	Matrix<IntPlaintextEncoding> numerator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);
	Matrix<IntPlaintextEncoding> denominator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	cc.DecryptMatrix(kp.secretKey, deserResult, &numerator2, &denominator2);

	std::cout << "numerator row 1 = " << numerator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator2(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator2(1, 0).EvalToInt(plaintextModulus) << std::endl;

}

void EvalLinRegressionFV3() {

	usint plaintextModulus = 256;
	usint relWindow = 16;
	float stdDev = 4;

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(plaintextModulus, 1.006, relWindow, stdDev, 0, 3, 0);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	std::cout << "RationalCiphertext s/d test" << std::endl;
	Ciphertext<ILVector2n> one(cc), two(cc), three(cc);
	ILVector2n onevec(cc.GetElementParams()), twovec(cc.GetElementParams()), threevec(cc.GetElementParams());
	onevec = { 1 };
	twovec = { 2 };
	threevec = { 3 };
	one.SetElement(onevec);
	two.SetElement(twovec);
	three.SetElement(threevec);
	RationalCiphertext<ILVector2n> aninteger(three);
	RationalCiphertext<ILVector2n> areal(one, two);

	Serialized rc;
	std::cout << "Integer: " << std::flush;
	if (aninteger.Serialize(&rc)) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if (newOne.Deserialize(rc)) {
			std::cout << "Deserialized! " << (aninteger == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Serialized rc2;
	std::cout << "Real: " << std::flush;
	if (areal.Serialize(&rc2)) {
		std::cout << "Serialized! " << std::flush;

		RationalCiphertext<ILVector2n> newOne(cc);
		if (newOne.Deserialize(rc2)) {
			std::cout << "Deserialized! " << (areal == newOne) << std::flush;
		}
	}
	std::cout << std::endl;

	Matrix<RationalCiphertext<ILVector2n>> mmm([cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); });
	Serialized mmmS;
	if (SerializableHelper::ReadSerializationFromFile("matrix.json", &mmmS)) {
		std::cout << "Trying to deserialize file" << std::endl;
		if (mmm.Deserialize(mmmS)) {
			std::cout << "Deserialized matrix" << std::endl;
		}
		else {
			std::cout << "r,c is" << mmm.GetRows() << "," << mmm.GetCols() << std::endl;
			const Matrix<RationalCiphertext<ILVector2n>>::data_t& e = mmm.GetData();
			std::cout << e.size() << std::endl;
			for (size_t i = 0; i<e.size(); i++)
				std::cout << i << ":" << e.at(i).size() << std::endl;
		}
	}

	double diff, start, finish;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 3);

	for (size_t i = 0; i < 3; ++i) {
		for (size_t j = 0; j < 3; ++j) {
			xP(i, j) = 101 % (2 * i + j + 1);
		}
	}

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);

	for (size_t i = 0; i < 3; ++i) {
		for (size_t j = 0; j < 1; ++j) {
			yP(i, j) = 99 % (2 * i + 5 * j + 1);
		}
	}

	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	std::cout << "Key generation started" << std::endl;

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	cc.EvalMultKeyGen(kp.secretKey);

	std::cout << "Key generation ended" << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Encryption execution time for the x matrix: " << "\t" << diff << " ms" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	std::cout << "MATRIX: " << y->GetRows() << "," << y->GetCols() << std::endl;

	Serialized rcm;
	Matrix<RationalCiphertext<ILVector2n>> newMat([cc]() { return make_unique<RationalCiphertext<ILVector2n>>(cc); });
	if (y->Serialize(&rcm)) {
		std::cout << "Matrix serialized" << std::endl;
		//		SerializableHelper::SerializationToStream(rcm, std::cout);
		//		std::cout << std::endl;

		if (newMat.Deserialize(rcm)) {
			std::cout << "Matrix deserialized" << std::endl;

			if (y->GetRows() != newMat.GetRows()) {
				std::cout << "row # mismatch" << std::endl;
			}
			if (y->GetCols() != newMat.GetCols()) {
				std::cout << "col # mismatch" << std::endl;
			}

			for (size_t r = 0; r<y->GetRows(); r++) {
				for (size_t c = 0; c<y->GetCols(); c++) {
					if ((*y)(r, c) != newMat(r, c)) {
						std::cout << "element mismatch at " << r << "," << c << std::endl;
					}
				}
			}

			std::cout << "DONE CHECKING" << std::endl;
		}
	}

	////////////////////////////////////////////////////////////
	//Linear Regression
	////////////////////////////////////////////////////////////

	std::cout << "\nComputing linear regression... " << std::endl;

	start = currentDateTime();

	auto result = cc.EvalLinRegression(x, y);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Linear regression execution time: " << "\t" << diff << " ms\n" << std::endl;

	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << result->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << result->GetCols() << std::endl;

	std::cout << "\nComputing linear regression from deserialized data... " << std::endl;

	auto deserResult = cc.EvalLinRegression(x, std::make_shared<Matrix<RationalCiphertext<ILVector2n>>>(newMat));
	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << deserResult->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << deserResult->GetCols() << std::endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	Matrix<IntPlaintextEncoding> numerator = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);
	Matrix<IntPlaintextEncoding> denominator = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);

	cc.DecryptMatrix(kp.secretKey, result, &numerator, &denominator);

	std::cout << "numerator row 1 = " << numerator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 3 = " << numerator(2, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 3 = " << denominator(2, 0).EvalToInt(plaintextModulus) << std::endl;

	std::cout << "on deserialized" << std::endl;
	Matrix<IntPlaintextEncoding> numerator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);
	Matrix<IntPlaintextEncoding> denominator2 = Matrix<IntPlaintextEncoding>(zeroAlloc, 3, 1);

	cc.DecryptMatrix(kp.secretKey, deserResult, &numerator2, &denominator2);

	std::cout << "numerator row 1 = " << numerator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 2 = " << numerator2(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "numerator row 3 = " << numerator2(2, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 1 = " << denominator2(0, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 2 = " << denominator2(1, 0).EvalToInt(plaintextModulus) << std::endl;
	std::cout << "denominator row 3 = " << denominator2(2, 0).EvalToInt(plaintextModulus) << std::endl;

}


void RationalTests() {

	//usint relWindow = 8;

	usint plaintextModulus = 256;
	usint m = 16;
	ILVector2n::Integer modulus("256");
	ILVector2n::Integer rootOfUnity("453444631");

	shared_ptr<ILVector2n::Params> ep(new ILVector2n::Params(m, modulus, rootOfUnity));
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextNull(ep, plaintextModulus);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	double diff, start, finish;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	// Set the plaintext matrices

	auto zeroAlloc = [=]() { return make_unique<IntPlaintextEncoding>(); };

	Matrix<IntPlaintextEncoding> xP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 2);

	std::vector<uint32_t> vectorOfInts1 = { 1,0,1,1,0,1,0,1 };
	xP(0, 0) = vectorOfInts1;

	std::vector<uint32_t> vectorOfInts2 = { 1,1,0,1,0,1,1,0 };
	xP(0, 1) = vectorOfInts2;

	std::vector<uint32_t> vectorOfInts3 = { 1,1,1,1,0,1,0,1 };
	xP(1, 0) = vectorOfInts3;

	std::vector<uint32_t> vectorOfInts4 = { 1,0,0,1,0,1,1,0 };
	xP(1, 1) = vectorOfInts4;

	Matrix<IntPlaintextEncoding> yP = Matrix<IntPlaintextEncoding>(zeroAlloc, 2, 1);

	std::vector<uint32_t> vectorOfInts5 = { 1,1,1,0,0,1,0,1 };
	yP(0, 0) = vectorOfInts5;

	std::vector<uint32_t> vectorOfInts6 = { 1,0,0,1,0,1,1,0 };
	yP(1, 0) = vectorOfInts6;


	////////////////////////////////////////////////////////////
	//Perform the key generation operations.
	////////////////////////////////////////////////////////////

	std::cout << "Key generation started" << std::endl;

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	//generate the evaluate key
	cc.EvalMultKeyGen(kp.secretKey);

	std::cout << "Key generation ended" << std::endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> x = cc.EncryptMatrix(kp.publicKey, xP);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Encryption execution time for the x matrix: " << "\t" << diff << " ms" << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> y = cc.EncryptMatrix(kp.publicKey, yP);

	//testing

	// two constructors
	RationalCiphertext<ILVector2n> testCipher(cc,true);
	RationalCiphertext<ILVector2n> testCipher2((*x)(0, 0));
	RationalCiphertext<ILVector2n> testCipher3((*x)(0, 1));


	std::cout << "First operand" << std::endl;
	std::cout << testCipher2.GetNumerator()->GetElement() << std::endl;

	std::cout << "second operand" << std::endl;
	std::cout << testCipher3.GetNumerator()->GetElement() << std::endl;

	RationalCiphertext<ILVector2n> testCipherResult = testCipher2 + testCipher3;

	std::cout << "result of addition" << std::endl;
	std::cout << testCipherResult.GetNumerator()->GetElement() << std::endl;

	testCipherResult = testCipher2 - testCipher3;

	std::cout << "result of subtraction" << std::endl;
	std::cout << testCipherResult.GetNumerator()->GetElement() << std::endl;

	testCipherResult = testCipher2 * testCipher3;

	std::cout << "result of multiplication" << std::endl;
	std::cout << testCipherResult.GetNumerator()->GetElement() << std::endl;

	testCipher2 += testCipher3;

	std::cout << "result of in-place addition" << std::endl;
	std::cout << testCipher2.GetNumerator()->GetElement() << std::endl;

	testCipher3 = -testCipher2;

	std::cout << "result of negation" << std::endl;
	std::cout << testCipher3.GetNumerator()->GetElement() << std::endl;

	IntPlaintextEncoding plaintext1(vectorOfInts1);
	IntPlaintextEncoding plaintext2(vectorOfInts2);
	IntPlaintextEncoding plaintext3(vectorOfInts3);
	IntPlaintextEncoding plaintext4(vectorOfInts4);
	IntPlaintextEncoding plaintext5(vectorOfInts3);
	IntPlaintextEncoding plaintext6(vectorOfInts6);

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext3;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext4;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext5;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext6;

	ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2, true);

	start = currentDateTime();

	ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1, true);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Encryption execution time: " << "\t" << diff << " ms" << std::endl;

	ciphertext3 = cc.Encrypt(kp.publicKey, plaintext3, true);
	ciphertext4 = cc.Encrypt(kp.publicKey, plaintext4, true);
	ciphertext5 = cc.Encrypt(kp.publicKey, plaintext5, true);
	ciphertext6 = cc.Encrypt(kp.publicKey, plaintext6, true);

	auto zeroAllocRC = [=]() { return make_unique<RationalCiphertext<ILVector2n>>(cc,true); };

	Matrix<RationalCiphertext<ILVector2n>> xC(zeroAllocRC, 2, 2);

	xC(0, 0).SetNumerator(*ciphertext1[0]);
	xC(0, 1).SetNumerator(*ciphertext2[0]);
	xC(1, 0).SetNumerator(*ciphertext3[0]);
	xC(1, 1).SetNumerator(*ciphertext4[0]);

	Matrix<RationalCiphertext<ILVector2n>> yC(zeroAllocRC, 2, 1);

	yC(0, 0).SetNumerator(*ciphertext5[0]);
	yC(1, 0).SetNumerator(*ciphertext6[0]);

	Matrix<RationalCiphertext<ILVector2n>> product = xC * yC;

	std::cout << "matrix product completed successfully" << std::endl;
	std::cout << "Rows: " << product.GetRows() << std::endl;
	std::cout << "Columns: " << product.GetCols() << std::endl;

	auto xDeterminant = *zeroAllocRC();
	xC.Determinant(&xDeterminant);

	std::cout << "Determinant completed successfully." << std::endl;
	//xDeterminant.GetNumerator()->GetElement().PrintValues();

	auto xTranspose = xC.Transpose();
	std::cout << "Transpose completed successfully" << std::endl;
	std::cout << "Rows: " << xTranspose.GetRows() << std::endl;
	std::cout << "Columns: " << xTranspose.GetCols() << std::endl;

	auto xCofactorMatrix = xC.CofactorMatrix();
	std::cout << "CofactorMatrix completed successfully" << std::endl;
	std::cout << "Rows: " << xCofactorMatrix.GetRows() << std::endl;
	std::cout << "Columns: " << xCofactorMatrix.GetCols() << std::endl;

	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> xPtr(new Matrix<RationalCiphertext<ILVector2n>>(xC));
	shared_ptr<Matrix<RationalCiphertext<ILVector2n>>> yPtr(new Matrix<RationalCiphertext<ILVector2n>>(yC));

	auto result = cc.EvalLinRegression(xPtr, yPtr);
	std::cout << "Linear regression computation completed successfully" << std::endl;
	std::cout << "Rows in the numerator: " << result->GetRows() << std::endl;
	std::cout << "Columns in the numerator: " << result->GetCols() << std::endl;

}

void IntegerTests() {

	//usint relWindow = 8;

	usint plaintextModulus = 256;
	usint n = 8;
	ILVector2n::Integer modulus("536871001");
	ILVector2n::Integer rootOfUnity("322299632");

	shared_ptr<ILVector2n::Params> ep(new ILVector2n::Params(n, modulus, rootOfUnity));
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextNull(ep, plaintextModulus);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	double diff, start, finish;

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp;

	std::vector<uint32_t> vectorOfInts1 = { 1,0,1,1,0,1,0,1 };
	IntPlaintextEncoding plaintext1(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = { 1,1,0,1,0,1,1,0 };
	IntPlaintextEncoding plaintext2(vectorOfInts2);

	std::vector<uint32_t> vectorOfInts3 = { 1,1,1,1,0,1,0,1 };
	IntPlaintextEncoding plaintext3(vectorOfInts3);

	std::vector<uint32_t> vectorOfInts4 = { 1,0,0,1,0,1,1,0 };
	IntPlaintextEncoding plaintext4(vectorOfInts4);

	std::vector<uint32_t> vectorOfInts5 = { 1,1,1,0,0,1,0,1 };
	IntPlaintextEncoding plaintext5(vectorOfInts3);

	std::vector<uint32_t> vectorOfInts6 = { 1,0,0,1,0,1,1,0 };
	IntPlaintextEncoding plaintext6(vectorOfInts6);

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	kp = cc.KeyGen();

	if (!kp.good()) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext1;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext2;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext3;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext4;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext5;
	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext6;

	ciphertext2 = cc.Encrypt(kp.publicKey, plaintext2, true);

	start = currentDateTime();

	ciphertext1 = cc.Encrypt(kp.publicKey, plaintext1, true);

	finish = currentDateTime();
	diff = finish - start;

	std::cout << "Encryption execution time: " << "\t" << diff << " ms" << std::endl;

	ciphertext3 = cc.Encrypt(kp.publicKey, plaintext3, true);
	ciphertext4 = cc.Encrypt(kp.publicKey, plaintext4, true);
	ciphertext5 = cc.Encrypt(kp.publicKey, plaintext5, true);
	ciphertext6 = cc.Encrypt(kp.publicKey, plaintext6, true);

	auto zeroAlloc = [=]() { return make_unique<Ciphertext<ILVector2n>>(cc); };

	Matrix<Ciphertext<ILVector2n>> x(zeroAlloc, 2, 2);

	x(0, 0) = *ciphertext1[0];
	x(0, 1) = *ciphertext2[0];
	x(1, 0) = *ciphertext3[0];
	x(1, 1) = *ciphertext4[0];

	Matrix<Ciphertext<ILVector2n>> y(zeroAlloc, 2, 1);

	y(0, 0) = *ciphertext5[0];
	y(1, 0) = *ciphertext6[0];

	Matrix<Ciphertext<ILVector2n>> product = x * y;

	std::cout << "matrix product completed successfully" << std::endl;
	std::cout << "Rows: " << product.GetRows() << std::endl;
	std::cout << "Columns: " << product.GetCols() << std::endl;

	auto xDeterminant = *zeroAlloc();
	x.Determinant(&xDeterminant);

	std::cout << "Determinant completed successfully. The value is " << std::endl;
	xDeterminant.GetElement().PrintValues();

	auto xTranspose = x.Transpose();
	std::cout << "Transpose completed successfully" << std::endl;
	std::cout << "Rows: " << xTranspose.GetRows() << std::endl;
	std::cout << "Columns: " << xTranspose.GetCols() << std::endl;

	auto xCofactorMatrix = x.CofactorMatrix();
	std::cout << "CofactorMatrix completed successfully" << std::endl;
	std::cout << "Rows: " << xCofactorMatrix.GetRows() << std::endl;
	std::cout << "Columns: " << xCofactorMatrix.GetCols() << std::endl;
	
}
