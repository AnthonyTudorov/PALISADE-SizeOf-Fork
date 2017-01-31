//Hi Level Execution/Demonstration
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version:
	v00.01
Last Edited:
	6/17/2015 4:37AM
List of Authors:
	TPOC:
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
Description:
	Demo used for evaluating specific operations

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <iostream>
#include <fstream>

#include "math/matrix.h"
#include "math/matrix.cpp"
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

#include "utils/debug.h"

//using namespace std;
using namespace lbcrypto;
void EvalLinRegressionNull();
//double currentDateTime();


#include <iterator>

int main() {

	EvalLinRegressionNull();

	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	std::cin.get();

	return 0;
}

void EvalLinRegressionNull() {

	//usint relWindow = 8;

	usint plaintextModulus = 256;
	usint n = 8;

	//float stdDev = 4;

	//Set crypto parametes
	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::getCryptoContextNull(plaintextModulus,n);

	//CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextFV(
	//	plaintextModulus, 0, "0", "0",
	//	relWindow, stdDev, "0", mode, "0", "0", 0, 9, 1.006);
	cc.Enable(ENCRYPTION);
	cc.Enable(SHE);

	double diff, start, finish;

	//start = currentDateTime();

	//cc.GetEncryptionAlgorithm()->ParamsGen(cc.GetCryptoParameters(), 0, 1);

	//finish = currentDateTime();
	//diff = finish - start;

	//std::cout << "Parameter generation time: " << "\t" << diff << " ms" << std::endl;

	//std::cout << "n = " << cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	//std::cout << "log2 q = " << log2(cc.GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

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


	////////////////////////////////////////////////////////////
	//EvalMult Operation
	////////////////////////////////////////////////////////////

	//shared_ptr<LPEvalKey<ILVector2n>> evalKey;

	////generate the evaluate key
	//evalKey = cc.EvalMultKeyGen(kp.secretKey);

	//vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertextMult;

	//shared_ptr<Ciphertext<ILVector2n>> ciphertextTempMult;

	//start = currentDateTime();

	//ciphertextTempMult = cc.EvalMult(ciphertext1[0], ciphertext2[0], evalKey);

	//finish = currentDateTime();
	//diff = finish - start;

	//std::cout << "EvalMult execution time: " << "\t" << diff << " ms" << std::endl;

	//ciphertextMult.push_back(ciphertextTempMult);

	//IntPlaintextEncoding plaintextNewMult;

}
