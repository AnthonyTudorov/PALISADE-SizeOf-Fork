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
#include "math/backend.h"
//#include "math/cpu8bit/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
//#include <thread>
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
//#include "il2n.h"
#include "math/distrgen.h"
#include "crypto/lwecrypt.h"
#include "crypto/lwecrypt.cpp"
#include "crypto/lwepre.h"
#include "crypto/lwepre.cpp"
#include "crypto/lweahe.cpp"
#include "crypto/lweshe.cpp"
#include "lattice/ilvector2n.h"
#include "lattice/ilvectorarray2n.h"
#include "time.h"
#include "crypto/ciphertext.cpp"
//#include "vld.h"
#include <chrono>
//#include "gtest/gtest.h"
//#include "math/cpu8bit/binint.h"
//#include "math/cpu8bit/binvect.h"
//#include "math/cpu8bit/binmat.h"

#include "utils/serializablehelper.cpp"

using namespace std;
using namespace lbcrypto;

void NTRUPRE(int input);
double currentDateTime();

/**
 * @brief Input parameters for PRE example.
 */
struct SecureParams {
	usint m;			///< The ring parameter.
	BigBinaryInteger modulus;	///< The modulus
	BigBinaryInteger rootOfUnity;	///< The rootOfUnity
	usint relinWindow;		///< The relinearization window parameter.
};

int main(){
	
	
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


double currentDateTime()
{

	std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();

    time_t tnow = std::chrono::system_clock::to_time_t(now);
    tm *date = localtime(&tnow);
    date->tm_hour = 0;
    date->tm_min = 0;
    date->tm_sec = 0;

    auto midnight = std::chrono::system_clock::from_time_t(mktime(date));

	return std::chrono::duration <double, std::milli>(now - midnight).count();
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
	
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	ByteArray plaintext = "N";
	
	usint relWindow = 8;
	//usint relWindow = 4;

	// The comments below provide a high-security parameterization for prototype use.  If this code were verified/certified for high-security applications, we would say that the following parameters would be appropriate for "production" use.
	//usint m = 2048;
	//BigBinaryInteger modulus("8590983169");
	//BigBinaryInteger rootOfUnity("4810681236");
	//ByteArray plaintext = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";
	//usint relWindow = 8;
	
	SecureParams const SECURE_PARAMS[] = {
//<<<<<<< HEAD
//=======
		//{ 2048, BigBinaryInteger("8589987841"), BigBinaryInteger("2678760785"), 1 }, //r = 8
//>>>>>>> 98034a0563cc8cab2eb1c179288561a65ad5a7f0
		{ 2048, BigBinaryInteger("268441601"), BigBinaryInteger("16947867"), 1 }, //r = 1
		{ 2048, BigBinaryInteger("536881153"), BigBinaryInteger("267934765"), 2 }, // r = 2
		{ 2048, BigBinaryInteger("1073750017"), BigBinaryInteger("180790047"), 4 },  // r = 4
		{ 2048, BigBinaryInteger("8589987841"), BigBinaryInteger("2678760785"), 8 }, //r = 8
		{ 4096, BigBinaryInteger("2199023288321"), BigBinaryInteger("1858080237421"), 16 }  // r= 16
		//{ 2048, CalltoModulusComputation(), CalltoRootComputation, 0 }  // r= 16
	};

	//usint m = SECURE_PARAMS[input].m;
	//BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	//BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	//usint relWindow = SECURE_PARAMS[input].relinWindow;

	//ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	////ByteArray plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");


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
	LPCryptoParametersLWE<ILVector2n> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
	//cryptoParams.SetPlaintextModulus(BigBinaryInteger("4"));  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(stdDev);			// Set the noise parameters.
	cryptoParams.SetRelinWindow(relWindow);				// Set the relinearization window
	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg(stdDev);			// Create the noise generator

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
	LPPublicKeyLWENTRU<ILVector2n> pk(cryptoParams);
	LPPrivateKeyLWENTRU<ILVector2n> sk(cryptoParams);

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LPAlgorithmLWENTRU<ILVector2n> algorithm;

	bool successKeyGen=false;

	std::cout <<"\n" <<  "Running key generation..." << std::endl;

	start = currentDateTime();

	successKeyGen = algorithm.KeyGen(pk,sk,dgg);	// This is the core function call that generates the keys.

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
    ptxt.Pad<ZeroPad>(m/16);
	//ptxt.Pad<ZeroPad>(m/8);

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	algorithm.Encrypt(pk,dgg,ptxt,&ciphertext);	// This is the core encryption operation.

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

	LPAlgorithmPRELWENTRU<ILVector2n> algorithmPRE;

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LPPublicKeyLWENTRU<ILVector2n> newPK(cryptoParams);
	LPPrivateKeyLWENTRU<ILVector2n> newSK(cryptoParams);

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	start = currentDateTime();

	successKeyGen = algorithmPRE.KeyGen(newPK,newSK,dgg);	// This is the same core key generation operation.

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

	LPEvalKeyLWENTRU<ILVector2n> evalKey(cryptoParams);

	start = currentDateTime();

	algorithmPRE.ProxyKeyGen(newPK, sk, dgg , &evalKey);  // This is the core re-encryption operation.

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

	algorithmPRE.ReEncrypt(evalKey, ciphertext,&newCiphertext);  // This is the core re-encryption operation.

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

	DecodingResult result1 = algorithmPRE.Decrypt(newSK,newCiphertext,&plaintextNew2);  // This is the core decryption operation.
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

	std::cout << "---------------------------START JSON FACIlTY TESTING------------------------------" << endl;

	string jsonInputBuffer = "";
	string jsonFileName = "";
	SerializableHelper jsonHelper;

	unordered_map <string, string> testMap1;
	testMap1 = pk.Serialize(testMap1, "Enc");
	jsonFileName = jsonHelper.GetJsonFileName(testMap1);
	cout << "jsonFileName:  " << jsonFileName << endl;
	jsonInputBuffer = jsonHelper.GetJsonString(testMap1);
	cout << "pk jsonInputBuffer:  " << jsonInputBuffer << endl;
	jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);

	testMap1 = jsonHelper.GetSerializationMap("LPPublicKeyLWENTRU_Enc.txt");
	LPPublicKeyLWENTRU<ILVector2n> pk1;
	LPCryptoParametersLWE<ILVector2n> json_cryptoParamsPub;
	pk1.SetCryptoParameters(&json_cryptoParamsPub);
	pk1.Deserialize(testMap1);

	unordered_map <string, string> testMap2;
	testMap2 = sk.Serialize(testMap2, "Enc");
	jsonFileName = jsonHelper.GetJsonFileName(testMap2);
	cout << "jsonFileName:  " << jsonFileName << endl;
	jsonInputBuffer = jsonHelper.GetJsonString(testMap2);
	cout << "sk jsonInputBuffer:  " << jsonInputBuffer << endl;
	jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);

	cout << "----------BEGIN LPPrivateKeyLWENTRU DESERIALIZATION TESTING----------" << endl;
	testMap2 = jsonHelper.GetSerializationMap("LPPrivateKeyLWENTRU_Enc.txt");
	LPPrivateKeyLWENTRU<ILVector2n> sk1;
	LPCryptoParametersLWE<ILVector2n> json_cryptoParamsPriv;
	sk1.SetCryptoParameters(&json_cryptoParamsPriv);
	sk1.Deserialize(testMap2);

	cout << "----------END LPPrivateKeyLWENTRU DESERIALIZATION TESTING----------" << endl;

	unordered_map <string, string> testMap3;
	testMap3 = ciphertext.Serialize(testMap3, "Enc");
	jsonFileName = jsonHelper.GetJsonFileName(testMap3);
	cout << "jsonFileName:  " << jsonFileName << endl;
	jsonInputBuffer = jsonHelper.GetJsonString(testMap3);
	cout << "ciphertext jsonInputBuffer:  " << jsonInputBuffer << endl;
	jsonHelper.OutputRapidJsonFile(jsonInputBuffer, jsonFileName);

	cout << "----------BEGIN CIPHERTEXT DESERIALIZATION TESTING----------" << endl;
	testMap3 = jsonHelper.GetSerializationMap("Ciphertext_Enc.txt");
	Ciphertext<ILVector2n> c1;
	c1.Deserialize(testMap3);
	cout << "----------END CIPHERTEXT DESERIALIZATION TESTING----------" << endl;

	/****UNCOMMENT TO TEST DECRYPT WITH DESERIALIZED PrivateKey and Ciphertext*****/
	cout << "----------BEGIN LPAlgorithmLWENTRU.Decrypt TESTING----------" << endl;
	ByteArrayPlaintextEncoding testPlaintextRec;

	cout << "YURIY: In Source.cpp sk1 PlaintextModulus: " << sk1.GetCryptoParameters().GetPlaintextModulus() << endl;

	DecodingResult testResult = algorithm.Decrypt(sk1, c1, &testPlaintextRec);
	testPlaintextRec.Unpad<ZeroPad>();
	cout << "Recovered plaintext from Decrypt: " << testPlaintextRec << endl;
	cout << "----------END LPAlgorithmLWENTRU.Decrypt TESTING----------" << endl;

	std::cout << "---------------------------END JSON FACIlTY TESTING------------------------------" << endl;

	std::cout << "Execution completed.  Please any key to finish." << std::endl;

	fout.close();

	//system("pause");

}


