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
void Multiply();
void MultiplyTwo();
void MultiplyThree();

int main() {

	//PKE();
	//SwitchCRT();
	//Multiply();
	MultiplyTwo();
	MultiplyThree();

	//std::cout << "Please press any key to continue..." << std::endl;

	//cin.get();
	return 0;
}


void PKE() {

	std::cout << "\n===========TESTING PKE===============: " << std::endl;

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

	std::cout << "\n===========TESTING CRT SWITCH===============: " << std::endl;

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
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 10, 0, OPTIMIZED,11);

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

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus S:\n" << paramsS->GetModulus() << std::endl;
	std::cout << "before switch:\n" << resultA.GetValAtIndex(0) << std::endl;
	std::cout << "after switch:\n" << resultB.GetValAtIndex(0) << std::endl;

}

void Multiply() {

	std::cout << "\n===========TESTING POLYNOMIAL MULTIPLICATION - ONE TERM IS CONSTANT POLYNOMIAL===============: " << std::endl;

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

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsFV->GetDCRTParamsQS();

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

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsFV->GetDCRTPolyInverseTable(),
			cryptoParamsFV->GetDCRTPolyqDivqiModsiTable(), cryptoParamsFV->GetDCRTPolyqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsFV->GetDCRTPolyInverseTable(),
			cryptoParamsFV->GetDCRTPolyqDivqiModsiTable(), cryptoParamsFV->GetDCRTPolyqModsiTable());

	std::cout << "Ended CRT Expansion" << std::endl;

	Poly resultExpanded = a.CRTInterpolate();

	Poly resultExpandedB = b.CRTInterpolate();

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus Q*S:\n" << a.GetParams()->GetModulus() << std::endl;
	std::cout << "before expansion:\n" << result.GetValAtIndex(0) << std::endl;
	std::cout << "after expansion:\n" << resultExpanded.GetValAtIndex(0) << std::endl;

	std::cout << "b before expansion - no signed correction: " << bPoly.GetValAtIndex(0) << std::endl;

	if (bPoly.GetValAtIndex(0) > bPoly.GetModulus()>>1)
		std::cout << "b before expansion: -" << bPoly.GetModulus() - bPoly.GetValAtIndex(0) << std::endl;
	else
		std::cout << "b before expansion: " << bPoly.GetValAtIndex(0) << std::endl;

	std::cout << "b after expansion - no signed correction: " << resultExpandedB.GetValAtIndex(0) << std::endl;
	if (resultExpandedB.GetValAtIndex(0) > resultExpandedB.GetModulus()>>1)
		std::cout << "b after expansion: -" << resultExpandedB.GetModulus() - resultExpandedB.GetValAtIndex(0) << std::endl;
	else
		std::cout << "b after expansion: " << resultExpandedB.GetValAtIndex(0) << std::endl;

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

	if (resultC.GetValAtIndex(0) > resultC.GetModulus()>>1)
		std::cout << "result C: -" << resultC.GetModulus() - resultC.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result C: " << resultC.GetValAtIndex(0) << std::endl;

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsFV->GetDCRTPolyMultIntTable(),cryptoParamsFV->GetDCRTPolyMultFloatTable());

	Poly resultRounded = rounded.CRTInterpolate();

	if (resultRounded.GetValAtIndex(0) > resultRounded.GetModulus()>>1)
		std::cout << "result: " << resultRounded.GetModulus() - resultRounded.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result: " << resultRounded.GetValAtIndex(0) << std::endl;

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsFV->GetDCRTPolySInverseTable(),
			cryptoParamsFV->GetDCRTPolysDivsiModqiTable(), cryptoParamsFV->GetDCRTPolysModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	if (resultRoundedQ.GetValAtIndex(0) > resultRoundedQ.GetModulus()>>1)
		std::cout << "result: " << resultRoundedQ.GetModulus() - resultRoundedQ.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result: " << resultRoundedQ.GetValAtIndex(0) << std::endl;

}

void MultiplyTwo() {

	std::cout << "\n===========TESTING POLYNOMIAL MULTIPLICATION - UNIFORM AND GAUSSIAN RANDOM POLYNOMIALS===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the FV scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	//double diff, start, finish;

	int relWindow = 1;
	usint plaintextModulus = 1<<15;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	shared_ptr<CryptoContext<DCRTPoly>> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 2, 0, OPTIMIZED,3);

	// enable features that you wish to use
	//cryptoContext->Enable(ENCRYPTION);
	//cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersFV<DCRTPoly>> cryptoParamsFV = std::dynamic_pointer_cast<LPCryptoParametersFV<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsFV->GetDCRTParamsS();

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsFV->GetDCRTParamsQS();

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

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsFV->GetDCRTPolyInverseTable(),
			cryptoParamsFV->GetDCRTPolyqDivqiModsiTable(), cryptoParamsFV->GetDCRTPolyqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsFV->GetDCRTPolyInverseTable(),
			cryptoParamsFV->GetDCRTPolyqDivqiModsiTable(), cryptoParamsFV->GetDCRTPolyqModsiTable());

	std::cout << "Ended CRT Expansion" << std::endl;

	Poly resultExpanded = a.CRTInterpolate();

	Poly resultExpandedB = b.CRTInterpolate();

	BigInteger modulusQS = a.GetParams()->GetModulus();

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus Q*S:\n" << a.GetParams()->GetModulus() << std::endl;

	if (result.GetValAtIndex(0) > result.GetModulus()>>1)
		std::cout << "a before expansion: -" << result.GetModulus() - result.GetValAtIndex(0) << std::endl;
	else
		std::cout << "a before expansion: " << result.GetValAtIndex(0) << std::endl;

	if (resultExpanded.GetValAtIndex(0) > resultExpanded.GetModulus()>>1)
		std::cout << "a after expansion: -" << resultExpanded.GetModulus() - resultExpanded.GetValAtIndex(0) << std::endl;
	else
		std::cout << "a after expansion: " << resultExpanded.GetValAtIndex(0) << std::endl;

	if (bPoly.GetValAtIndex(0) > bPoly.GetModulus()>>1)
		std::cout << "b before expansion: -" << bPoly.GetModulus() - bPoly.GetValAtIndex(0) << std::endl;
	else
		std::cout << "b before expansion: " << bPoly.GetValAtIndex(0) << std::endl;

	if (resultExpandedB.GetValAtIndex(0) > resultExpandedB.GetModulus()>>1)
		std::cout << "b after expansion: -" << resultExpandedB.GetModulus() - resultExpandedB.GetValAtIndex(0) << std::endl;
	else
		std::cout << "b after expansion: " << resultExpandedB.GetValAtIndex(0) << std::endl;

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

	if (resultC.GetValAtIndex(0) > resultC.GetModulus()>>1)
		std::cout << "result C: -" << resultC.GetModulus() - resultC.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result C: " << resultC.GetValAtIndex(0) << std::endl;

	if (cPoly.GetValAtIndex(0) > cPoly.GetModulus()>>1)
		std::cout << "result multiprecision C: -" << cPoly.GetModulus()-cPoly.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result multiprecision C: " << cPoly.GetValAtIndex(0) << std::endl;

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsFV->GetDCRTPolyMultIntTable(),cryptoParamsFV->GetDCRTPolyMultFloatTable());

	Poly resultRounded = rounded.CRTInterpolate();

	if (resultRounded.GetValAtIndex(0) > resultRounded.GetModulus()>>1)
		std::cout << "result: " << resultRounded.GetModulus() - resultRounded.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result: " << resultRounded.GetValAtIndex(0) << std::endl;

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsFV->GetDCRTPolySInverseTable(),
			cryptoParamsFV->GetDCRTPolysDivsiModqiTable(), cryptoParamsFV->GetDCRTPolysModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	if (resultRoundedQ.GetValAtIndex(0) > resultRoundedQ.GetModulus()>>1)
		std::cout << "result: " << resultRoundedQ.GetModulus() - resultRoundedQ.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result: " << resultRoundedQ.GetValAtIndex(0) << std::endl;


}

void MultiplyThree() {

	std::cout << "\n===========TESTING POLYNOMIAL MULTIPLICATION - TWO UNFORM RANDOM POLYNOMIALS===============: " << std::endl;

	std::cout << "\nThis code demonstrates the use of the FV scheme for basic homomorphic encryption operations. " << std::endl;
	std::cout << "This code shows how to auto-generate parameters during run-time based on desired plaintext moduli and security levels. " << std::endl;
	std::cout << "In this demonstration we use three input plaintext and show how to both add them together and multiply them together. " << std::endl;

	//Generate parameters.
	//double diff, start, finish;

	int relWindow = 1;
	usint plaintextModulus = 1<<15;
	double sigma = 3.2;
	double rootHermiteFactor = 1.006;

	//Set Crypto Parameters
	shared_ptr<CryptoContext<DCRTPoly>> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextFV(
			plaintextModulus, rootHermiteFactor, relWindow, sigma, 0, 2, 0, OPTIMIZED,3);

	// enable features that you wish to use
	//cryptoContext->Enable(ENCRYPTION);
	//cryptoContext->Enable(SHE);

	std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	const shared_ptr<ILDCRTParams<BigInteger>> params = cryptoContext->GetCryptoParameters()->GetElementParams();

	const shared_ptr<LPCryptoParametersFV<DCRTPoly>> cryptoParamsFV = std::dynamic_pointer_cast<LPCryptoParametersFV<DCRTPoly>>(cryptoContext->GetCryptoParameters());

	const shared_ptr<ILDCRTParams<BigInteger>> paramsS = cryptoParamsFV->GetDCRTParamsS();

	const shared_ptr<ILDCRTParams<BigInteger>> paramsQS = cryptoParamsFV->GetDCRTParamsQS();

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

	a.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsFV->GetDCRTPolyInverseTable(),
			cryptoParamsFV->GetDCRTPolyqDivqiModsiTable(), cryptoParamsFV->GetDCRTPolyqModsiTable());

	b.ExpandCRTBasis(paramsQS, paramsS, cryptoParamsFV->GetDCRTPolyInverseTable(),
			cryptoParamsFV->GetDCRTPolyqDivqiModsiTable(), cryptoParamsFV->GetDCRTPolyqModsiTable());

	std::cout << "Ended CRT Expansion" << std::endl;

	Poly resultExpanded = a.CRTInterpolate();

	Poly resultExpandedB = b.CRTInterpolate();

	BigInteger modulusQS = a.GetParams()->GetModulus();

	std::cout << "Big Modulus Q:\n" << params->GetModulus() << std::endl;
	std::cout << "Big Modulus Q*S:\n" << a.GetParams()->GetModulus() << std::endl;

	if (result.GetValAtIndex(0) > result.GetModulus()>>1)
		std::cout << "a before expansion: -" << result.GetModulus() - result.GetValAtIndex(0) << std::endl;
	else
		std::cout << "a before expansion: " << result.GetValAtIndex(0) << std::endl;

	if (resultExpanded.GetValAtIndex(0) > resultExpanded.GetModulus()>>1)
		std::cout << "a after expansion: -" << resultExpanded.GetModulus() - resultExpanded.GetValAtIndex(0) << std::endl;
	else
		std::cout << "a after expansion: " << resultExpanded.GetValAtIndex(0) << std::endl;

	if (bPoly.GetValAtIndex(0) > bPoly.GetModulus()>>1)
		std::cout << "b before expansion: -" << bPoly.GetModulus() - bPoly.GetValAtIndex(0) << std::endl;
	else
		std::cout << "b before expansion: " << bPoly.GetValAtIndex(0) << std::endl;

	if (resultExpandedB.GetValAtIndex(0) > resultExpandedB.GetModulus()>>1)
		std::cout << "b after expansion: -" << resultExpandedB.GetModulus() - resultExpandedB.GetValAtIndex(0) << std::endl;
	else
		std::cout << "b after expansion: " << resultExpandedB.GetValAtIndex(0) << std::endl;

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

	if (resultC.GetValAtIndex(0) > resultC.GetModulus()>>1)
		std::cout << "result C: -" << resultC.GetModulus() - resultC.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result C: " << resultC.GetValAtIndex(0) << std::endl;

	if (cPoly.GetValAtIndex(0) > cPoly.GetModulus()>>1)
		std::cout << "result multiprecision C: -" << cPoly.GetModulus()-cPoly.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result multiprecision C: " << cPoly.GetValAtIndex(0) << std::endl;

	DCRTPoly rounded = c.ScaleAndRound(paramsS,cryptoParamsFV->GetDCRTPolyMultIntTable(),cryptoParamsFV->GetDCRTPolyMultFloatTable());

	Poly resultRounded = rounded.CRTInterpolate();

	if (resultRounded.GetValAtIndex(0) > resultRounded.GetModulus()>>1)
		std::cout << "result: " << resultRounded.GetModulus() - resultRounded.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result: " << resultRounded.GetValAtIndex(0) << std::endl;

	DCRTPoly roundedQ = rounded.SwitchCRTBasis(params, cryptoParamsFV->GetDCRTPolySInverseTable(),
			cryptoParamsFV->GetDCRTPolysDivsiModqiTable(), cryptoParamsFV->GetDCRTPolysModqiTable());

	Poly resultRoundedQ = roundedQ.CRTInterpolate();

	if (resultRoundedQ.GetValAtIndex(0) > resultRoundedQ.GetModulus()>>1)
		std::cout << "result: " << resultRoundedQ.GetModulus() - resultRoundedQ.GetValAtIndex(0) << std::endl;
	else
		std::cout << "result: " << resultRoundedQ.GetValAtIndex(0) << std::endl;


}
