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


#include "../../lib/palisade.h"
#include "../../lib/palisadespace.h"


#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/encoding/byteplaintextencoding.h"

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
	string modulus;	///< The modulus
	string rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

#include <iterator>

int main() {

	std::cout << "Relinearization window : " << std::endl;
	std::cout << "0 (r = 1), 1 (r = 2), 2 (r = 4), 3 (r = 8), 4 (r = 16): [0] ";

	int input = 0;
	std::cin >> input;
	//cleans up the buffer
	std::cin.ignore();

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
		{ 2048, "268441601", "16947867", 1 }, //r = 1
		{ 2048, "536881153", "267934765", 2 }, // r = 2
		{ 2048, "1073750017", "180790047", 4 },  // r = 4
		{ 2048, "8589987841", "2678760785", 8 }, //r = 8
		{ 4096, "2199023288321", "1858080237421", 16 }  // r= 16
														//{ 2048, CalltoModulusComputation(), CalltoRootComputation, 0 }  // r= 16
	};

	usint m = SECURE_PARAMS[input].m;
	BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	usint relWindow = SECURE_PARAMS[input].relinWindow;

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");


	float stdDev = 4;

	//Prepare for parameters.
	shared_ptr<ILParams> params(new ILParams(m, modulus, rootOfUnity));

	//Set crypto parametes
	LPCryptoParametersBV<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger(2));  	// Set plaintext modulus.
																//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(relWindow);				// Set the relinearization window
	cryptoParams.SetElementParams(params);			// Set the initialization parameters.

	ofstream fout;
	fout.open("output.txt");


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	double diff, start, finish;

	start = currentDateTime();

	CryptoContext<ILVector2n> cc = CryptoContextFactory<ILVector2n>::genCryptoContextBV(&cryptoParams);
	cc.Enable(ENCRYPTION);
	cc.Enable(PRE);
	cc.Enable(SHE);

	//Precomputations for FTT
	ChineseRemainderTransformFTT::GetInstance().PreCompute(rootOfUnity, m, modulus);

	//Precomputations for DGG
	ILVector2n::PreComputeDggSamples(cc.GetGenerator(), std::static_pointer_cast<ILParams>(cc.GetCryptoParameters()->GetElementParams()));

	finish = currentDateTime();
	diff = finish - start;

	cout << "Precomputation time: " << "\t" << diff << " ms" << endl;
	fout << "Precomputation time: " << "\t" << diff << " ms" << endl;

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	//LPAlgorithmLTV<ILVector2n> algorithm;

	std::cout << "\n" << "Running key generation..." << std::endl;

	start = currentDateTime();

	// Initialize the public key containers.
	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	finish = currentDateTime();
	diff = finish - start;

	cout << "Key generation execution time: " << "\t" << diff << " ms" << endl;
	fout << "Key generation execution time: " << "\t" << diff << " ms" << endl;

	//fout<< currentDateTime()  << " pk = "<<pk.GetPublicElement().GetValues()<<endl;
	//fout<< currentDateTime()  << " sk = "<<sk.GetPrivateElement().GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	// Begin the initial encryption operation.
	cout << "\n" << "original plaintext: " << plaintext << "\n" << endl;
	fout << "\n" << "original plaintext: " << plaintext << "\n" << endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	ciphertext = cc.Encrypt(kp.publicKey, plaintext, false);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Encryption execution time: " << "\t" << diff << " ms" << endl;
	fout << "Encryption execution time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	std::cout << "\n" << "Running decryption..." << std::endl;

	start = currentDateTime();

	DecryptResult result = cc.Decrypt(kp.secretKey, ciphertext, &plaintextNew, false);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Decryption execution time: " << "\t" << diff << " ms" << endl;
	fout << "Decryption execution time: " << "\t" << diff << " ms" << endl;

	cout << "\n" << "decrypted plaintext (NTRU encryption): " << plaintextNew << "\n" << endl;
	fout << "\n" << "decrypted plaintext (NTRU encryption): " << plaintextNew << "\n" << endl;

	if (!result.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}



	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	start = currentDateTime();

	LPKeyPair<ILVector2n> newKp = cc.KeyGen();

	finish = currentDateTime();
	diff = finish - start;

	cout << "Key generation execution time: " << "\t" << diff << " ms" << endl;
	fout << "Key generation execution time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout << "\n" << "Generating proxy re-encryption key..." << std::endl;

	start = currentDateTime();

	// FIXME this can't use CryptoUtility because the calling sequence is wrong (2 private keys)
	shared_ptr<LPEvalKey<ILVector2n>> evalKey = cc.KeySwitchGen(kp.secretKey, newKp.secretKey );

	finish = currentDateTime();
	diff = finish - start;

	cout << "Re-encryption key generation time: " << "\t" << diff << " ms" << endl;
	fout << "Re-encryption key generation time: " << "\t" << diff << " ms" << endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;

	std::cout << "\n" << "Running re-encryption..." << std::endl;

	start = currentDateTime();

	newCiphertext = cc.ReEncrypt(evalKey, ciphertext);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Re-encryption execution time: " << "\t" << diff << " ms" << endl;
	fout << "Re-encryption execution time: " << "\t" << diff << " ms" << endl;

	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew2;

	std::cout << "\n" << "Running decryption of re-encrypted cipher..." << std::endl;

	start = currentDateTime();

	DecryptResult result1 = cc.Decrypt(newKp.secretKey, newCiphertext, &plaintextNew2, false);

	finish = currentDateTime();
	diff = finish - start;

	cout << "Decryption execution time: " << "\t" << diff << " ms" << endl;
	fout << "Decryption execution time: " << "\t" << diff << " ms" << endl;

	cout << "\n" << "decrypted plaintext (PRE Re-Encrypt): " << plaintextNew2 << "\n" << endl;
	fout << "\n" << "decrypted plaintext (PRE Re-Encrypt): " << plaintextNew2 << "\n" << endl;

	if (!result1.isValid) {
		std::cout << "Decryption failed!" << std::endl;
		exit(1);
	}

	std::cout << "Execution completed." << std::endl;

	fout.close();
}
