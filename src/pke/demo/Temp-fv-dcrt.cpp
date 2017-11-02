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

#include "encoding/byteplaintextencoding.h"
#include "encoding/packedintplaintextencoding.h"

#include "utils/debug.h"
#include <random>

#include "math/nbtheory.h"


using namespace std;
using namespace lbcrypto;


#include <iterator>

//Poly tests
void PKE();
void SwitchCRT();

int main() {

	std::cout << "\n===========TESTING PKE===============: " << std::endl;
	PKE();

	std::cout << "\n===========TESTING CRT SWITCH===============: " << std::endl;
	SwitchCRT();

	//std::cout << "Please press any key to continue..." << std::endl;

	//cin.get();
	return 0;
}


void PKE() {


	std::cout << "\nThis code demonstrates the use of the FV scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	double diff, start, finish;

	int relWindow = 1;
	usint plaintextModulus = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	shared_ptr<CryptoContext<DCRTPoly>> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 6, 0, OPTIMIZED,7);

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
	IntPlaintextEncoding plaintext(vectorOfInts);

	////////////////////////////////////////////////////////////
	// Encryption
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<DCRTPoly>>> ciphertext;

	start = currentDateTime();

	ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Encryption time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption of Ciphertext
	////////////////////////////////////////////////////////////

	IntPlaintextEncoding plaintextDec;

	start = currentDateTime();

	cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec, true);

	finish = currentDateTime();
	diff = finish - start;
	cout << "Decryption time: " << "\t" << diff << " ms" << endl;

	//std::cin.get();

	plaintextDec.resize(plaintext.size());

	cout << "\n Original Plaintext: \n";
	cout << plaintext << endl;

	cout << "\n Resulting Decryption of Ciphertext: \n";
	cout << plaintextDec << endl;

	cout << "\n";


}

void SwitchCRT() {


	std::cout << "\nThis code demonstrates the use of the FV scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	//double diff, start, finish;

	int relWindow = 1;
	usint plaintextModulus = 1<<31;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	shared_ptr<CryptoContext<DCRTPoly>> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 6, 0, OPTIMIZED,7);

	// enable features that you wish to use
	//cryptoContext->Enable(ENCRYPTION);
	//cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersFV<DCRTPoly>> cryptoParamsFV = std::dynamic_pointer_cast<LPCryptoParametersFV<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsFV->GetDCRTParamsS();

	typename DCRTPoly::DugType dug;

	//Generate the element "a" of the public key
	DCRTPoly a(dug, params, Format::COEFFICIENT);

	Poly resultA = a.CRTInterpolate();

	std::cout << "Starting CRT Basis switch" << std::endl;

	DCRTPoly b = a.SwitchCRTBasis(paramsS, cryptoParamsFV->GetDCRTPolyInverseTable(),
			cryptoParamsFV->GetDCRTPolyqDivqiModsiTable(), cryptoParamsFV->GetDCRTPolyqModsiTable());

	std::cout << "a mod s0 = " << resultA.GetValAtIndex(0).Mod(BigInteger(paramsS->GetParams()[0]->GetModulus().ConvertToInt())) << " modulus " << paramsS->GetParams()[0]->GetModulus() << std::endl;

	std::cout << "b mod s0 = " << b.GetElementAtIndex(0).GetValAtIndex(0) << " modulus = " << b.GetElementAtIndex(0).GetModulus() << std::endl;

	std::cout << "Finished CRT Basis switch" << std::endl;

	std::cout << "Starting interpolation" << std::endl;

	Poly resultB = b.CRTInterpolate();

	std::cout << "Finished interpolation" << std::endl;

	std::cout << "Big Modulus A:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus B:\n" << paramsS->GetModulus() << std::endl;
	std::cout << "before switch:\n" << resultA.GetValAtIndex(0) << std::endl;
	std::cout << "after switch:\n" << resultB.GetValAtIndex(0) << std::endl;

}

