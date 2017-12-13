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
 /*
FV RNS testing programs
*/

#include <iostream>
#include <fstream>


#include "palisade.h"


#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"


using namespace std;
using namespace lbcrypto;


#include <iterator>

//Poly tests
void PKE();
void SHETestCoeff();
void SHETestPacked();
void SHETestPackedInnerProduct();
void SwitchCRT();
void Multiply();
void MultiplyTwo();
void MultiplyThree();

int main() {

	PKE();
	SHETestCoeff();
	SHETestPacked();
	SHETestPackedInnerProduct();
	//SwitchCRT();
	//Multiply();
	//MultiplyTwo();
	//MultiplyThree();

	//std::cout << "Please press any key to continue..." << std::endl;

	//cin.get();
	return 0;
}


void PKE() {

	std::cout << "\n===========TESTING PKE===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 6, 0, OPTIMIZED,7);

	std::cout << "ran context gen" << std::endl;

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts = {1<<28,(1<<28)-1,1<<30,202,301,302,1<<30,402,501,502,601,602};
	Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	auto ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec->SetLength(plaintext->GetLength());

	cout << "\n Original Plaintext: \n";
	cout << plaintext << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintextDec << endl;

	cout << "\n";


}

void SHETestCoeff() {

	std::cout << "\n===========TESTING SHE - ADDITION, SUBTRACTION, NEGATION - COEFFICIENT ENCODING===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 6, 0, OPTIMIZED,7);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

	// Addition

	auto ciphertextSum = cryptoContext->EvalAdd(ciphertext1,ciphertext2);

	auto ciphertextSub = cryptoContext->EvalSub(ciphertext1,ciphertext2);

	auto ciphertextNeg = cryptoContext->EvalNegate(ciphertext1);


	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSum, &plaintextDec);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	Plaintext plaintextDecSub;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSub, &plaintextDecSub);
	plaintextDecSub->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecNeg;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextNeg, &plaintextDecNeg);
	plaintextDecNeg->SetLength(plaintext1->GetLength());

	plaintextDec->SetLength(plaintext1->GetLength());

	cout << "\n Original Plaintext #1: \n";
	cout << plaintext1 << endl;

	cout << "\n Original Plaintext #2: \n";
	cout << plaintext2 << endl;

	cout << "\n Resulting Decryption of the Sum: \n";
	cout << plaintextDec << endl;

	cout << "\n Resulting Decryption of the Subtraction: \n";
	cout << plaintextDecSub << endl;

	cout << "\n Resulting Decryption of the Negation: \n";
	cout << plaintextDecNeg << endl;

	cout << "\n";

}

void SHETestPacked() {

	std::cout << "\n===========TESTING SHE - ADDITION, SUBTRACTION, NEGATION - PACKED ENCODING===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 536903681;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 6, 0, OPTIMIZED,7);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	start = currentDateTime();

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

	// Operations

	auto ciphertextSum = cryptoContext->EvalAdd(ciphertext1,ciphertext2);

	auto ciphertextSub = cryptoContext->EvalSub(ciphertext1,ciphertext2);

	auto ciphertextNeg = cryptoContext->EvalNegate(ciphertext1);

	start = currentDateTime();

	auto ciphertextMul = cryptoContext->EvalMultNoRelin(ciphertext1,ciphertext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - #1: " << "\t" << diff << " ms" << endl;


	start = currentDateTime();

	auto ciphertextCube = cryptoContext->EvalMultNoRelin(ciphertextMul,ciphertext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - #2: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	Plaintext plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSum, &plaintextDec);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecSub;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextSub, &plaintextDecSub);
	plaintextDecSub->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecNeg;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextNeg, &plaintextDecNeg);
	plaintextDecNeg->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecMul;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul, &plaintextDecMul);
	plaintextDecMul->SetLength(plaintext1->GetLength());

	Plaintext plaintextDecCube;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextCube, &plaintextDecCube);
	plaintextDecCube->SetLength(plaintext1->GetLength());

	cout << "\n Original Plaintext #1: \n";
	cout << plaintext1 << endl;

	cout << "\n Original Plaintext #2: \n";
	cout << plaintext2 << endl;

	cout << "\n Resulting Decryption of the Sum: \n";
	cout << plaintextDec << endl;

	cout << "\n Resulting Decryption of the Subtraction: \n";
	cout << plaintextDecSub << endl;

	cout << "\n Resulting Decryption of the Negation: \n";
	cout << plaintextDecNeg << endl;

	cout << "\n Resulting Decryption of the Multiplication: \n";
	cout << plaintextDecMul << endl;

	cout << "\n Resulting Decryption of the computing the Cube: \n";
	cout << plaintextDecCube << endl;

	cout << "\n";

	start = currentDateTime();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);
	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalMult key generation time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	auto ciphertextRelin = cryptoContext->EvalMult(ciphertext1,ciphertext2);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Homomorphic multiplication time - with relinearization: " << "\t" << diff << " ms" << endl;

	Plaintext plaintextDecRelin;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextRelin, &plaintextDecRelin);
	plaintextDecRelin->SetLength(plaintext1->GetLength());

	cout << "\n Resulting Decryption of the Multiplication with Relinearization: \n";
	cout << plaintextDecRelin << endl;

	cout << "\n";

	start = currentDateTime();

	auto evalKeys = cryptoContext->EvalAutomorphismKeyGen(keyPair.secretKey,{5,25});

	finish = currentDateTime();
	diff = finish - start;
	cout << "Automorphism key gen time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	auto ciphertextRotated = cryptoContext->EvalAutomorphism(ciphertext1, 5, *evalKeys);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Automorphism time: " << "\t" << diff << " ms" << endl;

	Plaintext plaintextDecRotated;
	cryptoContext->Decrypt(keyPair.secretKey, ciphertextRotated, &plaintextDecRotated);
	plaintextDecRotated->SetLength(plaintext1->GetLength());
	cout << plaintextDecRotated << endl;

}

void SHETestPackedInnerProduct() {

	std::cout << "\n===========TESTING SHE - INNER PRODUCT - PACKED ENCODING===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	usint ptm = 268460033;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;
	usint batchSize = 16;

	BigInteger modulusP(ptm);

	EncodingParams encodingParams(new EncodingParamsImpl(ptm,batchSize));

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			encodingParams, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,3);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	// Initialize Public Key Containers
	LPKeyPair<DCRTPoly> keyPair;

	////////////////////////////////////////////////////////////
	// Perform Key Generation Operation
	////////////////////////////////////////////////////////////

	std::cout << "Running key generation (used for source data)..." << std::endl;

	start = currentDateTime();

	keyPair = cryptoContext->KeyGen();

	finish = currentDateTime();
	diff = finish - start;
	cout << "Key generation time: " << "\t" << diff << " ms" << endl;

	if( !keyPair.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	// Encode source data
	////////////////////////////////////////////////////////////

	std::vector<uint32_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

	std::vector<uint32_t> vectorOfInts2 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////

	std::cout << "starting encryption" << std::endl;

	start = currentDateTime();

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

	// Operations

	start = currentDateTime();

	cryptoContext->EvalSumKeyGen(keyPair.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalSumKeyGen time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	finish = currentDateTime();
	diff = finish - start;
	cout << "EvalMulKeyGen time: " << "\t" << diff << " ms" << endl;

	start = currentDateTime();

	auto result = cryptoContext->EvalInnerProduct(ciphertext1, ciphertext2, batchSize);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Inner product time: " << "\t" << diff << " ms" << endl;

	Plaintext intArrayNew;

	cryptoContext->Decrypt(keyPair.secretKey, result, &intArrayNew);

	intArrayNew->SetLength(plaintext1->GetLength());

	std::cout << "Sum = " << intArrayNew->GetPackedValue()[0] << std::endl;

	std::cout << "All components (other slots randomized) = " << intArrayNew << std::endl;

}

void SwitchCRT() {

	std::cout << "\n===========TESTING CRT SWITCH===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	//double diff, start, finish;

	usint ptm = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 7, 0, OPTIMIZED,8);

	// enable features that you wish to use
	//cryptoContext->Enable(ENCRYPTION);
	//cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();

	typename DCRTPoly::DugType dug;

	//Generate the element "a" of the public key
	const DCRTPoly a(dug, params, Format::COEFFICIENT);

	Poly resultA = a.CRTInterpolate();

	std::cout << "Starting CRT Basis switch" << std::endl;

	const DCRTPoly b = a.SwitchCRTBasis(paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	std::cout << "a mod s0 = " << resultA.at(0).Mod(BigInteger(paramsS->GetParams()[0]->GetModulus().ConvertToInt())) << " modulus " << paramsS->GetParams()[0]->GetModulus() << std::endl;
	std::cout << "b mod s0 = " << b.GetElementAtIndex(0).at(0) << " modulus = " << b.GetElementAtIndex(0).GetModulus() << std::endl;

	std::cout << "Finished CRT Basis switch" << std::endl;

	std::cout << "Starting interpolation" << std::endl;

	Poly resultB = b.CRTInterpolate();

	std::cout << "Finished interpolation" << std::endl;

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus S:\n" << paramsS->GetModulus() << std::endl;
	std::cout << "before switch:\n" << resultA.at(0) << std::endl;
	std::cout << "after switch:\n" << resultB.at(0) << std::endl;

}

void Multiply() {

	std::cout << "\n===========TESTING POLYNOMIAL MULTIPLICATION - ONE TERM IS CONSTANT POLYNOMIAL===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	//double diff, start, finish;

	usint ptm = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 5, 0, OPTIMIZED,6);

	// enable features that you wish to use
	//cryptoContext->Enable(ENCRYPTION);
	//cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsBFVrns->GetDCRTParamsQS();

	typename DCRTPoly::DugType dug;

	//DCRTPoly a(params, Format::COEFFICIENT,true);

	//Generate uninform element
	DCRTPoly a(dug, params, Format::COEFFICIENT);
	//Generate uninform element
	//DCRTPoly b(dug, params, Format::COEFFICIENT);
	DCRTPoly b(params, Format::COEFFICIENT,true);

	b = b + (uint64_t)1976860313128;

	b = b.Negate();

	Poly result = a.CRTInterpolate();

	Poly bPoly = b.CRTInterpolate();

	std::cout << "\n=====STEP 1: Expanding polynomials from Q to Q*S CRT basis=======\n" << std::endl;

	std::cout << "Starting CRT Expansion" << std::endl;

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	a.SwitchFormat();

	b.SwitchFormat();

	std::cout << "Ended CRT Expansion" << std::endl;

	Poly resultExpanded = a.CRTInterpolate();

	Poly resultExpandedB = b.CRTInterpolate();

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus Q*S:\n" << a.GetParams()->GetModulus() << std::endl;
	std::cout << "before expansion:\n" << result.at(0) << std::endl;
	std::cout << "after expansion:\n" << resultExpanded.at(0) << std::endl;

	std::cout << "b before expansion - no signed correction: " << bPoly.at(0) << std::endl;

	if (bPoly.at(0) > bPoly.GetModulus()>>1)
		std::cout << "b before expansion: -" << bPoly.GetModulus() - bPoly.at(0) << std::endl;
	else
		std::cout << "b before expansion: " << bPoly.at(0) << std::endl;

	std::cout << "b after expansion - no signed correction: " << resultExpandedB.at(0) << std::endl;
	if (resultExpandedB.at(0) > resultExpandedB.GetModulus()>>1)
		std::cout << "b after expansion: -" << resultExpandedB.GetModulus() - resultExpandedB.at(0) << std::endl;
	else
		std::cout << "b after expansion: " << resultExpandedB.at(0) << std::endl;

	std::cout << "\n=====STEP 2: Polynomial multiplication=======\n" << std::endl;

	std::cout << "Starting multiplication" << std::endl;

	// Convert from coefficient polynomial representation to evaluation one
	a.SwitchFormat();
	b.SwitchFormat();

	// Polynomial multiplication in Q*S CRT basis
	DCRTPoly c = a*b;

	// Put it back in coefficient representation
	c.SwitchFormat();

	std::cout << "Ended multiplication" << std::endl;

	Poly resultC = c.CRTInterpolate();

	if (resultC.at(0) > resultC.GetModulus()>>1)
		std::cout << "result C: -" << resultC.GetModulus() - resultC.at(0) << std::endl;
	else
		std::cout << "result C: " << resultC.at(0) << std::endl;

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsBFVrns->GetCRTMultIntTable(),cryptoParamsBFVrns->GetCRTMultFloatTable());

	Poly resultRounded = rounded.CRTInterpolate();

	if (resultRounded.at(0) > resultRounded.GetModulus()>>1)
		std::cout << "result: " << resultRounded.GetModulus() - resultRounded.at(0) << std::endl;
	else
		std::cout << "result: " << resultRounded.at(0) << std::endl;

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsBFVrns->GetCRTSInverseTable(),
			cryptoParamsBFVrns->GetCRTsDivsiModqiTable(), cryptoParamsBFVrns->GetCRTsModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	if (resultRoundedQ.at(0) > resultRoundedQ.GetModulus()>>1)
		std::cout << "result: " << resultRoundedQ.GetModulus() - resultRoundedQ.at(0) << std::endl;
	else
		std::cout << "result: " << resultRoundedQ.at(0) << std::endl;

}

void MultiplyTwo() {

	std::cout << "\n===========TESTING POLYNOMIAL MULTIPLICATION - UNIFORM AND GAUSSIAN RANDOM POLYNOMIALS===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	//double diff, start, finish;

	usint ptm = 1<<15;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,3);

	// enable features that you wish to use
	//cryptoContext->Enable(ENCRYPTION);
	//cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsBFVrns->GetDCRTParamsQS();

	typename DCRTPoly::DugType dug;

	//tested dgg up to 4000000 - worked correctly
	typename DCRTPoly::DggType dgg(400000);

	//typename DCRTPoly::TugType tug;

	//DCRTPoly a(params, Format::COEFFICIENT,true);

	//Generate uninform element
	//DCRTPoly a(dgg, params, Format::COEFFICIENT);
	DCRTPoly a(dug, params, Format::COEFFICIENT);
	//Generate uninform element
	DCRTPoly b(dgg, params, Format::COEFFICIENT);
	//DCRTPoly b(dug, params, Format::COEFFICIENT);
	//DCRTPoly b(dug, params, Format::COEFFICIENT);

	//DCRTPoly b(params, Format::COEFFICIENT,true);

	//b = b + 1675879;

	Poly result = a.CRTInterpolate();

	std::cout << "\n=====STEP 1: Expanding polynomials from Q to Q*S CRT basis=======\n" << std::endl;

	Poly aPoly = a.CRTInterpolate();

	Poly bPoly = b.CRTInterpolate();

	std::cout << "Starting CRT Expansion" << std::endl;

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	a.SwitchFormat();

	b.SwitchFormat();

	std::cout << "Ended CRT Expansion" << std::endl;

	Poly resultExpanded = a.CRTInterpolate();

	Poly resultExpandedB = b.CRTInterpolate();

	BigInteger modulusQS = a.GetParams()->GetModulus();

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus Q*S:\n" << a.GetParams()->GetModulus() << std::endl;

	if (result.at(0) > result.GetModulus()>>1)
		std::cout << "a before expansion: -" << result.GetModulus() - result.at(0) << std::endl;
	else
		std::cout << "a before expansion: " << result.at(0) << std::endl;

	if (resultExpanded.at(0) > resultExpanded.GetModulus()>>1)
		std::cout << "a after expansion: -" << resultExpanded.GetModulus() - resultExpanded.at(0) << std::endl;
	else
		std::cout << "a after expansion: " << resultExpanded.at(0) << std::endl;

	if (bPoly.at(0) > bPoly.GetModulus()>>1)
		std::cout << "b before expansion: -" << bPoly.GetModulus() - bPoly.at(0) << std::endl;
	else
		std::cout << "b before expansion: " << bPoly.at(0) << std::endl;

	if (resultExpandedB.at(0) > resultExpandedB.GetModulus()>>1)
		std::cout << "b after expansion: -" << resultExpandedB.GetModulus() - resultExpandedB.at(0) << std::endl;
	else
		std::cout << "b after expansion: " << resultExpandedB.at(0) << std::endl;

	std::cout << "\n=====STEP 2: Polynomial multiplication=======\n" << std::endl;

	std::cout << "Starting multiplication" << std::endl;

	// Convert from coefficient polynomial representation to evaluation one

	//std::cout << " a format = " <<  a.GetFormat()  << std::endl;
	//std::cout << " b format = " <<  b.GetFormat()  << std::endl;
	a.SwitchFormat();
	b.SwitchFormat();
	//std::cout << " a format = " <<  a.GetFormat()  << std::endl;
	//std::cout << " b format = " <<  b.GetFormat()  << std::endl;

	// Polynomial multiplication in Q*S CRT basis
	DCRTPoly c = a*b;

	//std::cout << " c format = " <<  c.GetFormat()  << std::endl;

	// Put it back in coefficient representation
	c.SwitchFormat();

	std::cout << "Ended multiplication" << std::endl;

	std::cout << "Starting multiprecision polynomial multiplication" << std::endl;

	BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
	BigInteger root("859703842628303907691187858658134128225754111718143879712783");
	usint m = 8192;

	shared_ptr<ILParams> paramsPoly(new ILParams(m, modulus, root));

	std::cout << "modulus = " << aPoly.GetModulus() << std::endl;

	aPoly.SwitchModulus(modulus,root);

	std::cout << "modulus after = " << aPoly.GetModulus() << std::endl;

	bPoly.SwitchModulus(modulus,root);

	// Convert from coefficient polynomial representation to evaluation one
	aPoly.SwitchFormat();
	bPoly.SwitchFormat();

	// Polynomial multiplication in Q*S CRT basis
	Poly cPoly = aPoly*bPoly;

	// Put it back in coefficient representation
	cPoly.SwitchFormat();

	std::cout << "Ended multiprecision multiplication" << std::endl;


	Poly resultC = c.CRTInterpolate();

	if (resultC.at(0) > resultC.GetModulus()>>1)
		std::cout << "result C: -" << resultC.GetModulus() - resultC.at(0) << std::endl;
	else
		std::cout << "result C: " << resultC.at(0) << std::endl;

	if (cPoly.at(0) > cPoly.GetModulus()>>1)
		std::cout << "result multiprecision C: -" << cPoly.GetModulus()-cPoly.at(0) << std::endl;
	else
		std::cout << "result multiprecision C: " << cPoly.at(0) << std::endl;

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsBFVrns->GetCRTMultIntTable(),cryptoParamsBFVrns->GetCRTMultFloatTable());

	Poly resultRounded = rounded.CRTInterpolate();

	if (resultRounded.at(0) > resultRounded.GetModulus()>>1)
		std::cout << "result: " << resultRounded.GetModulus() - resultRounded.at(0) << std::endl;
	else
		std::cout << "result: " << resultRounded.at(0) << std::endl;

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsBFVrns->GetCRTSInverseTable(),
			cryptoParamsBFVrns->GetCRTsDivsiModqiTable(), cryptoParamsBFVrns->GetCRTsModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	if (resultRoundedQ.at(0) > resultRoundedQ.GetModulus()>>1)
		std::cout << "result: " << resultRoundedQ.GetModulus() - resultRoundedQ.at(0) << std::endl;
	else
		std::cout << "result: " << resultRoundedQ.at(0) << std::endl;


}

void MultiplyThree() {

	std::cout << "\n===========TESTING POLYNOMIAL MULTIPLICATION - TWO UNFORM RANDOM POLYNOMIALS===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	//double diff, start, finish;

	usint ptm = 1<<15;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 2, 0, OPTIMIZED,3);

	// enable features that you wish to use
	//cryptoContext->Enable(ENCRYPTION);
	//cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersBFVrns<DCRTPoly>> cryptoParamsBFVrns = std::dynamic_pointer_cast<LPCryptoParametersBFVrns<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsBFVrns->GetDCRTParamsS();

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsBFVrns->GetDCRTParamsQS();

	typename DCRTPoly::DugType dug;

	//tested dgg up to 4000000 - worked correctly
	//typename DCRTPoly::DggType dgg(400000);

	//typename DCRTPoly::TugType tug;

	//DCRTPoly a(params, Format::COEFFICIENT,true);

	//Generate uninform element
	//DCRTPoly a(dgg, params, Format::COEFFICIENT);
	DCRTPoly a(dug, params, Format::COEFFICIENT);
	//Generate uninform element
	DCRTPoly b(dug, params, Format::COEFFICIENT);
	//DCRTPoly b(dug, params, Format::COEFFICIENT);
	//DCRTPoly b(dug, params, Format::COEFFICIENT);

	//DCRTPoly b(params, Format::COEFFICIENT,true);

	//b = b + 1675879;

	Poly result = a.CRTInterpolate();

	std::cout << "\n=====STEP 1: Expanding polynomials from Q to Q*S CRT basis=======\n" << std::endl;

	Poly aPoly = a.CRTInterpolate();

	Poly bPoly = b.CRTInterpolate();

	std::cout << "Starting CRT Expansion" << std::endl;

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsBFVrns->GetCRTInverseTable(),
			cryptoParamsBFVrns->GetCRTqDivqiModsiTable(), cryptoParamsBFVrns->GetCRTqModsiTable());

	a.SwitchFormat();

	b.SwitchFormat();

	std::cout << "Ended CRT Expansion" << std::endl;

	Poly resultExpanded = a.CRTInterpolate();

	Poly resultExpandedB = b.CRTInterpolate();

	BigInteger modulusQS = a.GetParams()->GetModulus();

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus Q*S:\n" << a.GetParams()->GetModulus() << std::endl;

	if (result.at(0) > result.GetModulus()>>1)
		std::cout << "a before expansion: -" << result.GetModulus() - result.at(0) << std::endl;
	else
		std::cout << "a before expansion: " << result.at(0) << std::endl;

	if (resultExpanded.at(0) > resultExpanded.GetModulus()>>1)
		std::cout << "a after expansion: -" << resultExpanded.GetModulus() - resultExpanded.at(0) << std::endl;
	else
		std::cout << "a after expansion: " << resultExpanded.at(0) << std::endl;

	if (bPoly.at(0) > bPoly.GetModulus()>>1)
		std::cout << "b before expansion: -" << bPoly.GetModulus() - bPoly.at(0) << std::endl;
	else
		std::cout << "b before expansion: " << bPoly.at(0) << std::endl;

	if (resultExpandedB.at(0) > resultExpandedB.GetModulus()>>1)
		std::cout << "b after expansion: -" << resultExpandedB.GetModulus() - resultExpandedB.at(0) << std::endl;
	else
		std::cout << "b after expansion: " << resultExpandedB.at(0) << std::endl;

	std::cout << "\n=====STEP 2: Polynomial multiplication=======\n" << std::endl;

	std::cout << "Starting multiplication" << std::endl;

	// Convert from coefficient polynomial representation to evaluation one

	//std::cout << " a format = " <<  a.GetFormat()  << std::endl;
	//std::cout << " b format = " <<  b.GetFormat()  << std::endl;
	a.SwitchFormat();
	b.SwitchFormat();
	//std::cout << " a format = " <<  a.GetFormat()  << std::endl;
	//std::cout << " b format = " <<  b.GetFormat()  << std::endl;

	// Polynomial multiplication in Q*S CRT basis
	DCRTPoly c = a*b;

	//std::cout << " c format = " <<  c.GetFormat()  << std::endl;

	// Put it back in coefficient representation
	c.SwitchFormat();

	std::cout << "Ended multiplication" << std::endl;

	std::cout << "Starting multiprecision polynomial multiplication" << std::endl;

	BigInteger modulus("1606938044258990275541962092341162602522202993782792836833281");
	BigInteger root("859703842628303907691187858658134128225754111718143879712783");
	usint m = 8192;

	shared_ptr<ILParams> paramsPoly(new ILParams(m, modulus, root));

	std::cout << "modulus = " << aPoly.GetModulus() << std::endl;

	aPoly.SwitchModulus(modulus,root);

	std::cout << "modulus after = " << aPoly.GetModulus() << std::endl;

	bPoly.SwitchModulus(modulus,root);

	// Convert from coefficient polynomial representation to evaluation one
	aPoly.SwitchFormat();
	bPoly.SwitchFormat();

	// Polynomial multiplication in Q*S CRT basis
	Poly cPoly = aPoly*bPoly;

	// Put it back in coefficient representation
	cPoly.SwitchFormat();

	std::cout << "Ended multiprecision multiplication" << std::endl;


	Poly resultC = c.CRTInterpolate();

	if (resultC.at(0) > resultC.GetModulus()>>1)
		std::cout << "result C: -" << resultC.GetModulus() - resultC.at(0) << std::endl;
	else
		std::cout << "result C: " << resultC.at(0) << std::endl;

	if (cPoly.at(0) > cPoly.GetModulus()>>1)
		std::cout << "result multiprecision C: -" << cPoly.GetModulus()-cPoly.at(0) << std::endl;
	else
		std::cout << "result multiprecision C: " << cPoly.at(0) << std::endl;

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsBFVrns->GetCRTMultIntTable(),cryptoParamsBFVrns->GetCRTMultFloatTable());

	Poly resultRounded = rounded.CRTInterpolate();

	if (resultRounded.at(0) > resultRounded.GetModulus()>>1)
		std::cout << "result: " << resultRounded.GetModulus() - resultRounded.at(0) << std::endl;
	else
		std::cout << "result: " << resultRounded.at(0) << std::endl;

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsBFVrns->GetCRTSInverseTable(),
			cryptoParamsBFVrns->GetCRTsDivsiModqiTable(), cryptoParamsBFVrns->GetCRTsModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	if (resultRoundedQ.at(0) > resultRoundedQ.GetModulus()>>1)
		std::cout << "result: " << resultRoundedQ.GetModulus() - resultRoundedQ.at(0) << std::endl;
	else
		std::cout << "result: " << resultRoundedQ.at(0) << std::endl;


}
