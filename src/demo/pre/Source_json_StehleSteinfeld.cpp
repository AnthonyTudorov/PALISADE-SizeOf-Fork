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

//GIT TEST

#include <iostream>
#include <fstream>
#include "../../lib/math/backend.h"
//#include "../../lib/math/cpu8bit/backend.h"
#include "../../lib/utils/inttypes.h"
#include "../../lib/math/nbtheory.h"
//#include <thread>
#include "../../lib/lattice/elemparams.h"
#include "../../lib/lattice/ilparams.h"
#include "../../lib/lattice/ildcrtparams.h"
#include "../../lib/lattice/ilelement.h"
//#include "../../lib/il2n.h"
#include "../../lib/math/distrgen.h"
#include "../../lib/crypto/lwecrypt.h"
#include "../../lib/crypto/lwecrypt.cpp"
#include "../../lib/crypto/lweautomorph.cpp"
#include "../../lib/crypto/lwepre.h"
#include "../../lib/crypto/lwepre.cpp"
#include "../../lib/crypto/lweahe.cpp"
#include "../../lib/crypto/lweshe.cpp"
#include "../../lib/crypto/lwefhe.cpp"
#include "../../lib/lattice/ilvector2n.h"
#include "../../lib/lattice/ilvectorarray2n.h"
#include "time.h"
#include "../../lib/crypto/ciphertext.cpp"
//#include "../../lib/vld.h"
#include <chrono>
//#include "../../lib/gtest/gtest.h"
//#include "../../lib/math/cpu8bit/binint.h"
//#include "../../lib/math/cpu8bit/binvect.h"
//#include "../../lib/math/cpu8bit/binmat.h"

#include "../../lib/utils/serializablehelper.h"
#include "../../lib/utils/debug.h"

using namespace std;
using namespace lbcrypto;

void NTRUPRE(int input);

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
	BigBinaryInteger plaintextModulus;
	float stdDev;
};

int main(){
	
	
	std::cout << "Paramter set : " << std::endl;
	std::cout << "0 (n = 1024, p = 2, r = 1), 1 (n = 1024, p = 2, r = 8), 2 (n = 2048, p = 2, r = 1), 3 (n = 2048, p = 16, r = 16), 4 (n = 4096, p = 16, r = 16), 5 (n = 8192, p = 16, r = 16), 6 (n = 4096, p = 256, r = 16): ";

	int input = 0;
	std::cin >> input;
	//cleans up the buffer
	cin.ignore();

	if ((input<0) || (input>6))
		input = 0;

	////NTRUPRE is where the core functionality is provided.
	NTRUPRE(input);
	//NTRUPRE(3);
	

	// The below lines clean up the memory use.
	//system("pause");

	////Hadi's code
	//usint m = 16;
	//BigBinaryInteger rootOfUnity("61564");
	//Format format = COEFFICIENT;

	//BigBinaryInteger modulu1;
 //   modulu1 = FindPrimeModulus(16, 20);
	//cout<<modulu1<<endl;

 //   BigBinaryInteger rootOfUnity1;
	//rootOfUnity1 = RootOfUnity(m, modulu1);

	//ILParams ilParams2(m, modulu1, rootOfUnity);


	//ILVector2n c2(ilParams2);
	//usint m2 = 16;
	//DiscreteGaussianGenerator d2(m2/2, modulu1);
	//BigBinaryVector x2 = d2.GenerateVector(m2/2);
	//c2.SetValues(x2, Format::COEFFICIENT);

	//c2.SwitchFormat();
	//c2.SwitchFormat();


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
	ByteArray plaintext = "N";
	usint relWindow = 8;
	*/

	// The comments below provide a high-security parameterization for prototype use.  If this code were verified/certified for high-security applications, we would say that the following parameters would be appropriate for "production" use.
	//usint m = 2048;
	//BigBinaryInteger modulus("8590983169");
	//BigBinaryInteger rootOfUnity("4810681236");
	//ByteArray plaintext = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";
	//usint relWindow = 8;
	
	SecureParams const SECURE_PARAMS[] = {
		{ 2048, BigBinaryInteger("8589987841"), BigBinaryInteger("8451304774"), 1, BigBinaryInteger("2"), 32.812 }, //n = 1024; r = 1; p = 2
		{ 2048, BigBinaryInteger("137439004673"), BigBinaryInteger("7643730114"), 8, BigBinaryInteger("2"),  71.6332 }, // r = 2
		{ 4096, BigBinaryInteger("17179926529"), BigBinaryInteger("1874048014"), 1, BigBinaryInteger("2"),  32.812 },  // r = 4
		{ 4096, BigBinaryInteger("72057594037948417"), BigBinaryInteger("12746853818308484"), 16, BigBinaryInteger("16"), 1511.83 }, // r = 2
		{ 8192, BigBinaryInteger("144115188076060673"), BigBinaryInteger("48914894759308182"), 16, BigBinaryInteger("16"), 1511.83 }, //n = 1024; r = 1; p = 2
		{ 16384, BigBinaryInteger("288230376151760897"), BigBinaryInteger("144972394728154060"), 16, BigBinaryInteger("16"), 1511.83  }, //n = 1024; r = 1; p = 2
		{ 8192, BigBinaryInteger("75557863725914323468289"), BigBinaryInteger("36933905409054618621009"), 16, BigBinaryInteger("256"), 41411.5 }, // log2 q = 83
		//{ 2048, CalltoModulusComputation(), CalltoRootComputation, 0 }  // r= 16
	};

	usint m = SECURE_PARAMS[input].m;
	BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	usint relWindow = SECURE_PARAMS[input].relinWindow;
	float stdDevStSt = SECURE_PARAMS[input].stdDev;
	BigBinaryInteger plaintextModulus(SECURE_PARAMS[input].plaintextModulus);

	ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");


	float stdDev = 4;

	ofstream fout;
	fout.open ("output.txt");


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	//Prepare for parameters.
	ILParams ilParams(m,modulus,rootOfUnity);

	//std::cout << ilParams.GetRootOfUnity() << std::endl;

	//Should eventually be replaced with the following code
	//ILParams ilParams;
	//ilParams.Initialize(m,bitLength);
	//Or
	//ilParams.Initialize(m,bitLenght,inputFile);

	//Set crypto parametes
	LPCryptoParametersStehleSteinfeld<ILVector2n> cryptoParams;
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
	cryptoParams.SetPlaintextModulus(plaintextModulus);  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetDistributionParameterStSt(stdDevStSt);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(relWindow);				// Set the relinearization window
	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg(stdDev);			// Create the noise generator
	cryptoParams.SetDiscreteGaussianGenerator(dgg);

	DiscreteGaussianGenerator dggStehleSteinfeld(stdDevStSt);			// Create the noise generator
	cryptoParams.SetDiscreteGaussianGeneratorStSt(dggStehleSteinfeld);

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
	LPPublicKeyLTV<ILVector2n> pk(cryptoParams);
	LPPrivateKeyLTV<ILVector2n> sk(cryptoParams);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LPPublicKeyEncryptionSchemeStehleSteinfeld<ILVector2n> algorithm;
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

	// Begin the initial encryption operation.
	cout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;
	fout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;

	Ciphertext<ILVector2n> ciphertext;
	ByteArrayPlaintextEncoding ptxt(plaintext);
    ptxt.Pad<ZeroPad>(m/16 * (plaintextModulus.GetMSB()-1));
	//ptxt.Pad<ZeroPad>(m/8);

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	algorithm.Encrypt(pk,ptxt,&ciphertext);	// This is the core encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"ciphertext: "<<ciphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	ByteArrayPlaintextEncoding plaintextNew;

	std::cout <<"\n"<< "Running decryption..." << std::endl;

	start = currentDateTime();

	DecodingResult result = algorithm.Decrypt(sk,ciphertext,&plaintextNew);  // This is the core decryption operation.
    plaintextNew.Unpad<ZeroPad>();

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;

	//cout << "ciphertext at" << ciphertext.GetIndexAt(2);

	if (!result.isValidCoding) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}
	//PRE SCHEME

	//system("pause");

	//LPAlgorithmPRELTV<ILVector2n> algorithmPRE;

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPPublicKeyLTV<ILVector2n> newPK(cryptoParams);
	LPPrivateKeyLTV<ILVector2n> newSK(cryptoParams);

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	start = currentDateTime();

	successKeyGen = algorithm.KeyGen(&newPK,&newSK);	// This is the same core key generation operation.

	finish = currentDateTime();
	diff = finish - start;

	cout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

//	cout<<"newPK = "<<newPK.GetPublicElement().GetValues()<<endl;
//	cout<<"newSK = "<<newSK.GetPrivateElement().GetValues()<<endl;
//	fout<<"newPK = "<<newPK.GetPublicElement().GetValues()<<endl;
//	fout<<"newSK = "<<newSK.GetPrivateElement().GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	LPEvalKeyLTV<ILVector2n> evalKey(cryptoParams);

	start = currentDateTime();

	algorithm.EvalKeyGen(newPK, sk, &evalKey);  // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	Ciphertext<ILVector2n> newCiphertext;

	std::cout <<"\n"<< "Running re-encryption..." << std::endl;

	start = currentDateTime();

	algorithm.ReEncrypt(evalKey, ciphertext, &newCiphertext);  // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	ByteArrayPlaintextEncoding plaintextNew2;

	std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	start = currentDateTime();

	DecodingResult result1 = algorithm.Decrypt(newSK,newCiphertext,&plaintextNew2);  // This is the core decryption operation.
    plaintextNew2.Unpad<ZeroPad>();

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;

	if (!result1.isValidCoding) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	cout << "Press any key to continue..." << endl;

		std::cin.get();

	std::cout << "----------------------START JSON FACILITY TESTING-------------------------" << endl;

	cout << "\n" << endl;

	ByteArray newPlaintext("1) SERIALIZE CRYPTO-OBJS TO FILE AS NESTED JSON STRUCTURES\n2) DESERIALIZE JSON FILES INTO CRYPTO-OBJS USED FOR CRYPTO-APIS");
	ByteArrayPlaintextEncoding newPtxt(newPlaintext);
	newPtxt.Pad<ZeroPad>(m / 2);
	cout << "Original Plaintext: " << endl;
	cout << newPlaintext << endl;

	cout << "\n" << endl;

	string jsonInputBuffer = "";
	string jsonFileName = "";
	SerializableHelper jsonHelper;

	cout << "---BEGIN LPPublicKeyLTV SERIALIZATION---" << endl;
	cout << "Serializing previously used pk object..." << endl;
	SerializationMap testMap1;
	if( pk.Serialize(testMap1, "Enc") ) {
		jsonFileName = jsonHelper.GetJsonFileName(testMap1);
		jsonInputBuffer = jsonHelper.GetJsonString(testMap1);
		jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);
		cout << "Serialization saved to " << jsonFileName + ".txt" << endl;
	}
	cout << "---END LPPublicKeyLTV SERIALIZATION TESTING---" << endl;

	cout << "---BEGIN LPPrivateKeyLTV SERIALIZATION---" << endl;
	cout << "Serializing previously used sk object..." << endl;
	SerializationMap testMap2;
	if( sk.Serialize(testMap2, "Enc") ) {
		jsonFileName = jsonHelper.GetJsonFileName(testMap2);
		jsonInputBuffer = jsonHelper.GetJsonString(testMap2);
		jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);
		cout << "Serialization saved to " << jsonFileName + ".txt" << endl;
	}
	cout << "---END LPPrivateKeyLTV SERIALIZATION---" << endl;

	cout << "---BEGIN LPPublicKeyLTV DESERIALIZATION---" << endl;
	jsonFileName = "LPPublicKeyLTV_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	testMap1 = jsonHelper.GetSerializationMap(jsonFileName);
	LPPublicKeyLTV<ILVector2n> pkDeserialized;
	LPCryptoParametersStehleSteinfeld<ILVector2n> json_cryptoParamsPub;
	pkDeserialized.SetCryptoParameters(&json_cryptoParamsPub);
	pkDeserialized.Deserialize(testMap1);
	cout << "Deserialized into pkDeserialized" << endl;
	cout << "---END LPPublicKeyLTV DESERIALIZATION---" << endl;

	cout << "---BEGIN LPPrivateKeyLTV DESERIALIZATION---" << endl;
	jsonFileName = "LPPrivateKeyLTV_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	testMap2 = jsonHelper.GetSerializationMap(jsonFileName);
	LPPrivateKeyLTV<ILVector2n> skDeserialized;
	LPCryptoParametersStehleSteinfeld<ILVector2n> json_cryptoParamsPriv;
	skDeserialized.SetCryptoParameters(&json_cryptoParamsPriv);
	skDeserialized.Deserialize(testMap2);
	cout << "Deserialized into skDeserialized" << endl;
	cout << "---END LPPrivateKeyLTV DESERIALIZATION---" << endl;

	cout << "\n" << endl;

	cout << "----------BEGIN LPAlgorithmLTV.Ecrypt TESTING----------" << endl;
	cout << "Calling Encrypt in LPAlgorithmLTV with deserialized instance of" << endl;
	cout << "LPPublicKeyLTV." << endl;
	Ciphertext<ILVector2n> testCiphertext;
	algorithm.Encrypt(pkDeserialized, newPtxt, &testCiphertext);
	cout << "----------END LPAlgorithmPRELTV.ReEcrypt TESTING----------" << endl;

	cout << "\n" << endl;

	cout << "---BEGIN CIPHERTEXT SERIALIZATION---" << endl;
	cout << "Serializing testCiphertext object generated by Encrypt TESTING..." << endl;
	SerializationMap testMap3;
	if( testCiphertext.Serialize(testMap3, "Enc") ) {
		jsonFileName = jsonHelper.GetJsonFileName(testMap3);
		jsonInputBuffer = jsonHelper.GetJsonString(testMap3);
		jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);
		cout << "Serialization saved to " << jsonFileName + ".txt" << endl;
	}
	cout << "---END CIPHERTEXT SERIALIZATION---" << endl;

	cout << "---BEGIN CIPHERTEXT DESERIALIZATION---" << endl;
	jsonFileName = "Ciphertext_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	testMap3 = jsonHelper.GetSerializationMap(jsonFileName);
	Ciphertext<ILVector2n> ciphertextDeserialized;
	if( ciphertextDeserialized.Deserialize(testMap3) )
		cout << "Deserialized into ciphertextDeserialized" << endl;
	cout << "---END CIPHERTEXT DESERIALIZATION---" << endl;

	cout << "\n" << endl;

	cout << "----------BEGIN LPAlgorithmLTV.Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithmLTV with deserialized instances of" << endl;
	cout << "LPPrivateKeyLTV and Ciphertext." << endl;
	ByteArrayPlaintextEncoding testPlaintextRec;
	DecodingResult testResult = algorithm.Decrypt(skDeserialized, ciphertextDeserialized, &testPlaintextRec);
	testPlaintextRec.Unpad<ZeroPad>();
	cout << "Recovered plaintext from call to Decrypt: " << endl;
	cout << testPlaintextRec << endl;
	cout << "----------END LPAlgorithmLTV.Decrypt TESTING----------" << endl;

	cout << "Press any key to continue..." << endl;

		std::cin.get();

	cout << "\n" << endl;

	cout << "---BEGIN LPEvalKeyLTV SERIALIZATION---" << endl;
	cout << "Serializing previously used evalKey object..." << endl;
	SerializationMap testMap4;
	if( evalKey.Serialize(testMap4, "Pre") ) {
		jsonFileName = jsonHelper.GetJsonFileName(testMap4);
		jsonInputBuffer = jsonHelper.GetJsonString(testMap4);
		jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);
		cout << "Serialization saved to " << jsonFileName + ".txt" << endl;
	}
	cout << "---END LPEvalKeyLTV SERIALIZATION TESTING---" << endl;

	cout << "---BEGIN LPEvalKeyLTV DESERIALIZATION---" << endl;
	jsonFileName = "LPEvalKeyLTV_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	testMap4 = jsonHelper.GetSerializationMap(jsonFileName);
	LPEvalKeyLTV<ILVector2n> evalKeyDeserialized;
	LPCryptoParametersStehleSteinfeld<ILVector2n> json_cryptoParamsEval;
	evalKeyDeserialized.SetCryptoParameters(&json_cryptoParamsEval);
	evalKeyDeserialized.Deserialize(testMap4);
	cout << "Deserialized into evalKeyDeserialized" << endl;
	cout << "---END LPEvalKeyLTV DESERIALIZATION---" << endl;

	cout << "\n" << endl;

	cout << "----------BEGIN LPAlgorithmPRELTV.ReEcrypt TESTING----------" << endl;
	cout << "Calling ReEncrypt in LPAlgorithmPRELTV with deserialized instances of" << endl;
	cout << "LPEvalKeyLTV and Ciphertext." << endl;
	Ciphertext<ILVector2n> preCiphertext;
	algorithm.ReEncrypt(evalKeyDeserialized, ciphertextDeserialized, &preCiphertext);
	cout << "----------END LPAlgorithmPRELTV.ReEcrypt TESTING----------" << endl;

	cout << "\n" << endl;

	cout << "---BEGIN PRE LPPrivateKeyLTV SERIALIZATION---" << endl;
	cout << "Serializing previously used newSK object..." << endl;
	SerializationMap testMap5;
	if( newSK.Serialize(testMap5, "Pre") ) {
		jsonFileName = jsonHelper.GetJsonFileName(testMap5);
		jsonInputBuffer = jsonHelper.GetJsonString(testMap5);
		jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);
		cout << "Serialization saved to " << jsonFileName + ".txt" << endl;
	}
	cout << "---END PRE LPPrivateKeyLTV SERIALIZATION---" << endl;

	cout << "---BEGIN PRE CIPHERTEXT SERIALIZATION---" << endl;
	cout << "Serializing preCiphertext object generated by ReEncrypt TESTING..." << endl;
	SerializationMap testMap6;
	if( preCiphertext.Serialize(testMap6, "Pre") ) {
		jsonFileName = jsonHelper.GetJsonFileName(testMap6);
		jsonInputBuffer = jsonHelper.GetJsonString(testMap6);
		jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);
		cout << "Serialization saved to " << jsonFileName + ".txt" << endl;
	}
	cout << "---END PRE CIPHERTEXT SERIALIZATION---" << endl;

	cout << "---BEGIN PRE LPPrivateKeyLTV DESERIALIZATION---" << endl;
	jsonFileName = "LPPrivateKeyLTV_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	testMap5 = jsonHelper.GetSerializationMap(jsonFileName);
	LPPrivateKeyLTV<ILVector2n> newSKDeserialized;
	LPCryptoParametersStehleSteinfeld<ILVector2n> json_cryptoParamsNewPriv;
	newSKDeserialized.SetCryptoParameters(&json_cryptoParamsNewPriv);
	newSKDeserialized.Deserialize(testMap5);
	cout << "Deserialized into newSKDeserialized" << endl;
	cout << "---END PRE LPPrivateKeyLTV DESERIALIZATION---" << endl;

	cout << "---BEGIN PRE CIPHERTEXT DESERIALIZATION---" << endl;
	jsonFileName = "Ciphertext_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	testMap3 = jsonHelper.GetSerializationMap(jsonFileName);
	Ciphertext<ILVector2n> preCiphertextDeserialized;
	preCiphertextDeserialized.Deserialize(testMap3);
	cout << "Deserialized into preCiphertextDeserialized" << endl;
	cout << "---END PRE CIPHERTEXT DESERIALIZATION---" << endl;

	cout << "\n" << endl;

	cout << "----------BEGIN LPAlgorithmPRELTV.Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithmPRELTV with deserialized instances of" << endl;
	cout << "PRE LPPrivateKeyLTV and PRE Ciphertext." << endl;
	ByteArrayPlaintextEncoding testPlaintextPreRec;
	DecodingResult testResult1 = algorithm.Decrypt(newSKDeserialized, preCiphertextDeserialized, &testPlaintextPreRec);
	testPlaintextPreRec.Unpad<ZeroPad>();
	cout << "Recovered plaintext from call to PRE Decrypt: " << endl;
	cout << testPlaintextPreRec << endl;
	cout << "----------END LPAlgorithmPRELTV.Decrypt TESTING----------" << endl;

	cout << "\n" << endl;

	std::cout << "----------------------END JSON FACILITY TESTING-------------------------" << endl;

	std::cout << "------------START STRING DESERIALIZATION TESTING---------------" << endl;

	cout << "\n" << endl;

	string jsonInStringTestBuff;

	SerializationMap testMap7;
	if( testCiphertext.Serialize(testMap7, "Enc") ) {
		jsonInStringTestBuff = jsonHelper.GetJsonString(testMap7);
		cout << "jsonInputBuffer: " << endl;
		cout << jsonInStringTestBuff << endl;
	}
	cout << "\n" << endl;

	SerializationMap testMap8;
	testMap8 = jsonHelper.GetSerializationMap(jsonInputBuffer.c_str());
	jsonInStringTestBuff = jsonHelper.GetJsonString(testMap8);
	cout << "Recovered jsonInputBuffer: " << endl;
	cout << jsonInStringTestBuff << endl;

	cout << "\n" << endl;

	std::cout << "------------END STRING DESERIALIZATION TESTING---------------" << endl;

	cout << "\n" << endl;

	std::cout << "Execution completed.  Please any key to finish." << std::endl;

	fout.close();

	//system("pause");

}


