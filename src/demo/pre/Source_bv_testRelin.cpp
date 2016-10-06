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
		Gyana Sahu, grs22@njit.edu
Description:
	This code exercises the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.
	In this code we:
		- Generate a key pair.
		- Encrypt a string of data.
		- Decrypt the data.
		- Generate a new key pair.
		- Generate a proxy re-encryption key.
		- Re-Encrypt the encrypted data.
		- Decrypt the re-encrypted data.
	We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor and may be closer to AES-256.

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

#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/encoding/byteplaintextencoding.h"
#include "../../lib/encoding/intplaintextencoding.h"
#include "../../lib/utils/cryptoutility.h"

#include "../../lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;
void NTRUPRE(int input);
//double currentDateTime();

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

#include <iterator>

int main() {

	std::cout << "Relinearization window : " << std::endl;
	std::cout << "0 (r = 1), 1 (r = 2), 2 (r = 4), 3 (r = 8), 4 (r = 16): [0] ";

	int input = 0;
	std::cin >> input;
	//cleans up the buffer
	cin.ignore();

	if ((input<0) || (input>4))
		input = 0;

	////NTRUPRE is where the core functionality is provided.
	NTRUPRE(input);
	//NTRUPRE(3);
	
	std::cin.get();
	ChineseRemainderTransformFTT::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();

	return 0;
}


//////////////////////////////////////////////////////////////////////
//	NTRUPRE is where the core functionality is provided.
//	In this code we:
//		- Generate a key pair.
//		- Encrypt a string of data.
//		- Decrypt the data.
//		- Generate a new key pair.
//		- Generate a proxy re-encryption key.
//		- Re-Encrypt the encrypted data.
//		- Decrypt the re-encrypted data.
//////////////////////////////////////////////////////////////////////
//	We provide two different paramet settings.
//	The low-security, highly efficient settings are commented out.
//	The high-security, less efficient settings are enabled by default.
//////////////////////////////////////////////////////////////////////
void NTRUPRE(int input) {

	//Set element params

	// Remove the comments on the following to use a low-security, highly efficient parameterization for integration and debugging purposes.
	/*
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	BytePlaintextEncoding plaintext = "N";
	*/

	// The comments below provide a high-security parameterization for prototype use.  If this code were verified/certified for high-security applications, we would say that the following parameters would be appropriate for "production" use.
	//usint m = 2048;
	//BigBinaryInteger modulus("8590983169");
	//BigBinaryInteger rootOfUnity("4810681236");
	//BytePlaintextEncoding plaintext = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";

	SecureParams const SECURE_PARAMS[] = {
		{ 2048, BigBinaryInteger("268441601"), BigBinaryInteger("16947867"), 1 }, //r = 1
		{ 2048, BigBinaryInteger("536881153"), BigBinaryInteger("267934765"), 2 }, // r = 2
		{ 2048, BigBinaryInteger("1073750017"), BigBinaryInteger("180790047"), 4 },  // r = 4
		{ 2048, BigBinaryInteger("8589987841"), BigBinaryInteger("2678760785"), 8 }, //r = 8
		{ 4096, BigBinaryInteger("2199023288321"), BigBinaryInteger("1858080237421"), 16 }  // r= 16
		//{ 2048, CalltoModulusComputation(), CalltoRootComputation, 0 }  // r= 16
	};

	/*usint m = SECURE_PARAMS[input].m;
	BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	usint relWindow = SECURE_PARAMS[input].relinWindow;*/

	usint m = 8;

	BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	usint relWindow = SECURE_PARAMS[input].relinWindow;


	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//Generating new cryptoparameters for when modulus reduction is done.
	std::vector<usint> vectorOfInts1 = {1,0,1,0};
	IntPlaintextEncoding intArray1(vectorOfInts1);

	float stdDev = 4;

	ofstream fout;
	fout.open ("output.txt");


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	//Prepare for parameters.
	ILParams ilParams(m,modulus,rootOfUnity);

	//Set crypto parametes
	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(relWindow);				// Set the relinearization window
	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg(stdDev);				// Create the noise generator
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	const ILParams &cpILParams = static_cast<const ILParams&>(cryptoParams.GetElementParams());

	double diff, start, finish;

	start = currentDateTime();

	//This code is run only when performing execution time measurements

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(dgg, ilParams);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Precomputation time: " << "\t" << diff << " ms" << endl;
	fout << "Precomputation time: " << "\t" << diff << " ms" << endl;

	// Initialize the public key containers.
	LPPublicKey<ILVector2n> pk(cryptoParams);
	LPPrivateKey<ILVector2n> sk(cryptoParams);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;


	LPPublicKeyEncryptionSchemeBV<ILVector2n> algorithm;
	algorithm.Enable(ENCRYPTION);
	algorithm.Enable(PRE);

	bool successKeyGen=false;

	std::cout <<"\n" <<  "Running key generation..." << std::endl;

	start = currentDateTime();

	successKeyGen = algorithm.KeyGen(&pk,&sk);	// This is the core function call that generates the keys.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	//fout<< currentDateTime()  << " pk = "<<pk.GetPublicElement().GetValues()<<endl;
	//fout<< currentDateTime()  << " sk = "<<sk.GetPrivateElement().GetValues()<<endl;

	if (!successKeyGen) {
		std::cout<<"Key generation failed!"<<std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	vector<Ciphertext<ILVector2n>> ciphertext;

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	CryptoUtility<ILVector2n>::Encrypt(algorithm, pk, intArray1, &ciphertext, false);	// This is the core encryption operation.


	std::cout << "Printing sk" << std::endl;

	sk.GetPrivateElement().PrintValues();

	std::vector<ILVector2n> skPowers = sk.GetPrivateElement().PowersOfBase(relWindow);

	for (usint i = 0; i < skPowers.size(); i++) {
		std::cout << "Printing skPowers vector: " << i << std::endl;
		skPowers.at(i).PrintValues();
	}

	const ILVector2n &x = ciphertext.at(0).GetElements().at(1);

	std::cout << "Printing ciphertext " << std::endl;

	x.PrintValues();

	std::vector<ILVector2n> cipherDecompose;
	
	x.BaseDecompose(relWindow, &cipherDecompose);

	for (usint i = 0; i < skPowers.size(); i++) {
		std::cout << "Printing cipherDecompose vector: " << i << std::endl;
		cipherDecompose.at(i).PrintValues();
	}

	ILVector2n finalAttached(skPowers.at(0)*cipherDecompose.at(0));

	for (usint i = 1; i < skPowers.size(); i++) {
		finalAttached += skPowers.at(i)*cipherDecompose.at(i);
	}

	std::cout << "Printing finalAttached: " << std::endl;
	finalAttached.PrintValues();

	auto resultCheck = x*sk.GetPrivateElement();

	std::cout << "Printing resultCheck: " << std::endl;

	resultCheck.PrintValues();


	IntPlaintextEncoding results;

	//CryptoUtility<ILVector2n>::Decrypt(algorithm, sk, ciphertext, &results, false);
	LPPublicKey<ILVector2n> pkNew(cryptoParams);
	LPPrivateKey<ILVector2n> skNew(cryptoParams);

	algorithm.KeyGen(&pkNew, &skNew);

	const DiscreteUniformGenerator dug(modulus);

	std::vector<ILVector2n> alpha;
	std::vector<ILVector2n> errors;
	std::vector<ILVector2n> beta;
	//generate alphas
	for (usint i = 0; i < skPowers.size(); i++) {
		ILVector2n a(dug, ilParams, Format::EVALUATION);
		alpha.push_back(std::move(a));
		ILVector2n ee(dgg, ilParams, Format::EVALUATION);
		errors.push_back(std::move(ee));
	}



	for (usint i = 0; i < skPowers.size(); i++) {
		//ILVector2n bb(alpha.at(i)*skNew.GetPrivateElement());
		ILVector2n bb(cryptoParams.GetPlaintextModulus()*errors.at(i));
		bb = bb - skPowers.at(i);
		beta.push_back(std::move(bb));
	}

	ILVector2n cipherC0(ciphertext.at(0).GetElements().at(0) );
	ILVector2n cipherC1(ciphertext.at(0).GetElements().at(1) );

	
	ILVector2n cipherC0Dash(cipherC0);
	for (usint i = 0; i < beta.size(); i++) {
		cipherC0Dash += cipherDecompose.at(i)*beta.at(i);
	}

	cipherC0Dash.PrintValues();

	/*ILVector2n cipherC1Dash(cipherDecompose.at(0)*alpha.at(0));
	for (usint i = 1; i < alpha.size(); i++) {
		cipherC1Dash += cipherDecompose.at(0)*alpha.at(0);
	}

	cipherC1Dash = cipherC1Dash*skNew.GetPrivateElement();

	cipherC0Dash = cipherC0Dash - cipherC1Dash;*/

	ILVector2n C1E(cipherDecompose.at(0)*errors.at(0));
	for (usint i = 1; i < cipherDecompose.size(); i++) {
		C1E = C1E + cipherDecompose.at(i)*errors.at(i);
	}

	C1E = cryptoParams.GetPlaintextModulus()*C1E;

	C1E.SwitchFormat();

	C1E.PrintValues();

	C1E.ModByTwo().PrintValues();

	C1E.SwitchFormat();

	auto checkC0Dash = cipherC0 - cipherC1*sk.GetPrivateElement() + C1E;

	checkC0Dash.PrintValues();

	//cipherC0Dash.SwitchFormat();

	//cipherC0Dash.PrintValues();

	//auto v (cipherC0Dash.ModByTwo());
	//v.PrintValues();

}
