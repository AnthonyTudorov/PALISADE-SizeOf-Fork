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

All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.

This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
*/

#include <iostream>
#include <fstream>
#include "binint.h"
#include "binmat.h"
#include "binvect.h"
#include "inttypes.h"
#include "nbtheory.h"
//#include <thread>
#include "ideals.h"
//#include "il2n.h"
#include "distrgen.h"
#include "lwecrypt.h"
#include "lwecrypt.cpp"
#include "lwepre.h"
#include "lwepre.cpp"
#include "il2n.h"
#include "time.h"
//#include "vld.h"
#include <chrono>

using namespace std;
using namespace lbcrypto;


BigBinaryVector& EncodeElementSource(const ByteArray &encoded, const BigBinaryInteger &modulus);

ByteArray EncodedElementSource(const BigBinaryVector& inp, const BigBinaryInteger &modulus);

struct DataParams;

void NTRUPRE_ForScript(DataParams &d);
void NTRUPRE(int input);
void CheckFFT();
void CheckCRT();
void CheckPolynomial();
void BigBinaryIntegerMemoryLeakTest();
void BigBinaryVectorMemoryLeakTest();
void ILVector2nMemoryLeakTest();
void DiscreteGaussianGeneratorTest();
void SimulationRunScript();
double currentDateTime();

//defination of input parameters for 
struct DataParams{
	usint ringDimension;
	BigBinaryInteger cipherTextModulus;
	BigBinaryInteger rootOfUnity;
	usint relWindow;
};


struct SecureParams {
	usint m;
	BigBinaryInteger modulus;
	BigBinaryInteger rootOfUnity;
	usint relinWindow;
};

int main(){


	//SimulationRunScript();


	
	//std::cout << "Relinearization window : " << std::endl;
	//std::cout << "0 (r = 1), 1 (r = 2), 2 (r = 4), 3 (r = 8), 4 (r = 16): [0]";
	
	int input = 0;
	//std::cin >> input;
	//cleans up the buffer
	//cin.ignore();

	//if ((input<0) || (input>4))
	//	input = 0;

	////NTRUPRE is where the core functionality is provided.
	NTRUPRE(input);
	//NTRUPRE(3);

	// The below lines clean up the memory use.
	//system("pause");
	std::cin.get();
	ChineseRemainderTransform::GetInstance().Destroy();
	NumberTheoreticTransform::GetInstance().Destroy();
	
	return 0;
}


double currentDateTime()
{
	
	std::chrono::time_point<std::chrono::high_resolution_clock> now = std::chrono::high_resolution_clock::now();
 
    time_t tnow = std::chrono::high_resolution_clock::to_time_t(now);
    tm *date = localtime(&tnow);
    date->tm_hour = 0;
    date->tm_min = 0;
    date->tm_sec = 0;

    auto midnight = std::chrono::high_resolution_clock::from_time_t(mktime(date));
 
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
	/*
	usint m = 16;
	BigBinaryInteger modulus("67108913");
	BigBinaryInteger rootOfUnity("61564");
	ByteArray plaintext = "N";
	*/

	// The comments below provide a high-security parameterization for prototype use.  If this code were verified/certified for high-security applications, we would say that the following parameters would be appropriate for "production" use.
	//usint m = 2048;
	//BigBinaryInteger modulus("8590983169");
	//BigBinaryInteger rootOfUnity("4810681236");
	//ByteArray plaintext = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW_NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";
	
	SecureParams const SECURE_PARAMS[] = {
		{ 2048, BigBinaryInteger("8590983169"), BigBinaryInteger("4810681236"), 1 }, //r = 1
		{ 2048, BigBinaryInteger("17179875329"), BigBinaryInteger("8079001841"), 2 }, // r = 2
		{ 2048, BigBinaryInteger("34359754753"), BigBinaryInteger("34316244289"), 4 },  // r = 4
		{ 2048, BigBinaryInteger("137439004673"), BigBinaryInteger("7643730114"), 8 }, //r = 8
		{ 4096, BigBinaryInteger("35184372121601"), BigBinaryInteger("16870007166633"), 16 }  // r= 16
	};

	usint m = SECURE_PARAMS[input].m;
	BigBinaryInteger modulus(SECURE_PARAMS[input].modulus);
	BigBinaryInteger rootOfUnity(SECURE_PARAMS[input].rootOfUnity);
	usint relWindow = SECURE_PARAMS[input].relinWindow;
	ByteArray plaintext = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW_NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";
	if (m == 4096)
		plaintext += plaintext;

	ofstream fout;
	fout.open ("output.txt");

	
	std::cout << "Cryptosystem initialization: Performing precomputations..." << std::endl;

	//Prepare for parameters.
	ILParams ilParams(m,modulus,rootOfUnity);
	
	//Set crypto parametes
	LP_CryptoParameters_LWE<ILVector2n,ILParams> cryptoParams;
	cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
	cryptoParams.SetDistributionParameter(4);			// Set the noise parameters.
	cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

	DiscreteGaussianGenerator dgg(4,modulus);			// Create the noise generator

	// Disrete Gaussian and FFT precomputations are done
	ILVector2n testElement(dgg,ilParams);
	testElement.SwitchFormat();

	// Initialize the public key containers.
	LP_PublicKey_LWE_NTRU<ILVector2n,ILParams> pk;

	LP_PrivateKey_LWE_NTRU<ILVector2n,ILParams> sk;
	sk.AccessCryptoParameters() = cryptoParams;
	pk.AccessCryptoParameters() = cryptoParams;
	
	//Regular LWE-NTRU encryption algorithm
	
	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	LP_Algorithm_LWE_NTRU<ILVector2n,ILParams> algorithm;

	bool successKeyGen=false;

	double diff, start, finish;

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

	ILVector2n ciphertext;

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	algorithm.Encrypt(pk,dgg,plaintext,&ciphertext);	// This is the core encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"ciphertext: "<<ciphertext.GetValues()<<endl;
	
	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	ByteArray plaintextNew;

	std::cout <<"\n"<< "Running decryption..." << std::endl;

	start = currentDateTime();

	DecodingResult result = algorithm.Decrypt(sk,ciphertext,&plaintextNew);  // This is the core decryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;

	if (!result.isValidCoding) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}
	//PRE SCHEME

	//system("pause");

	LP_Algorithm_PRE_LWE_NTRU<ILVector2n,ILParams> algorithmPRE;

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	LP_PublicKey_LWE_NTRU<ILVector2n,ILParams> newPK;
	LP_PrivateKey_LWE_NTRU<ILVector2n,ILParams> newSK;
	newSK.AccessCryptoParameters() = cryptoParams;
	newPK.AccessCryptoParameters() = cryptoParams;

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

	start = currentDateTime();

	std::vector<ILVector2n> &proxyGen = algorithmPRE.ProxyGen(newPK, sk, dgg, relWindow);  // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	ILVector2n newCiphertext;

	std::cout <<"\n"<< "Running re-encryption..." << std::endl;

	start = currentDateTime();

	algorithmPRE.ReEncrypt(proxyGen,cryptoParams, relWindow, ciphertext,&newCiphertext);  // This is the core re-encryption operation.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	ByteArray plaintextNew2;

	std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	start = currentDateTime();

	DecodingResult result1 = algorithmPRE.Decrypt(newSK,newCiphertext,&plaintextNew2);  // This is the core decryption operation.

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

	std::cout << "Execution completed.  Please any key to finish." << std::endl;

	fout.close();

	delete &proxyGen;

	//system("pause");
	
}


void NTRUPRE_ForScript(DataParams &d){

		//Set element params

		usint m = d.ringDimension * 2;
		BigBinaryInteger modulus(d.cipherTextModulus);
		BigBinaryInteger rootOfUnity(d.rootOfUnity);
		usint relWindow = d.relWindow;

		ByteArray originalString = "NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW_NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL";

		ByteArray plaintext;

		for (usint i = 0; i < d.ringDimension / 1024; i++)
			plaintext += originalString;

		std::cout << "Working plaintext  ::\n" << plaintext << std::endl;

		ofstream fout;
		fout.open("output.txt");


		std::cout << "Cryptosystem initialization: Performing precomputations..." << std::endl;

		//Prepare for parameters.
		ILParams ilParams(m, modulus, rootOfUnity);

		//Set crypto parametes
		LP_CryptoParameters_LWE<ILVector2n, ILParams> cryptoParams;
		cryptoParams.SetPlaintextModulus(BigBinaryInteger::TWO);  	// Set plaintext modulus.
		cryptoParams.SetDistributionParameter(4);			// Set the noise parameters.
		cryptoParams.SetElementParams(ilParams);			// Set the initialization parameters.

		DiscreteGaussianGenerator dgg(4, modulus);			// Create the noise generator

		// Disrete Gaussian and FFT precomputations are done
		ILVector2n testElement(dgg, ilParams);
		testElement.SwitchFormat();

		// Initialize the public key containers.
		LP_PublicKey_LWE_NTRU<ILVector2n, ILParams> pk;

		LP_PrivateKey_LWE_NTRU<ILVector2n, ILParams> sk;
		sk.AccessCryptoParameters() = cryptoParams;
		pk.AccessCryptoParameters() = cryptoParams;

		//Regular LWE-NTRU encryption algorithm

		////////////////////////////////////////////////////////////
		//Perform the key generation operation.
		////////////////////////////////////////////////////////////

		LP_Algorithm_LWE_NTRU<ILVector2n, ILParams> algorithm;

		bool successKeyGen = false;

		//double diff, start, finish;

		std::cout << "\n" << "Running key generation..." << std::endl;

		//start = currentDateTime();

		successKeyGen = algorithm.KeyGen(pk, sk, dgg);	// This is the core function call that generates the keys.

		//finish = currentDateTime();
		//diff = finish - start;

		//cout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
		//fout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

		//fout<< currentDateTime()  << " pk = "<<pk.GetPublicElement().GetValues()<<endl;
		//fout<< currentDateTime()  << " sk = "<<sk.GetPrivateElement().GetValues()<<endl;

		if (!successKeyGen) {
			std::cout << "Key generation failed!" << std::endl;
			exit(1);
		}

		////////////////////////////////////////////////////////////
		//Encryption
		////////////////////////////////////////////////////////////

		// Begin the initial encryption operation.
		cout << "\n" << "original plaintext: " << plaintext << "\n" << endl;
		fout << "\n" << "original plaintext: " << plaintext << "\n" << endl;

		ILVector2n ciphertext;

		std::cout << "Running encryption..." << std::endl;

		//start = currentDateTime();

		algorithm.Encrypt(pk, dgg, plaintext, &ciphertext);	// This is the core encryption operation.

		//finish = currentDateTime();
		//diff = finish - start;

		//cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
		//fout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

		//cout<<"ciphertext: "<<ciphertext.GetValues()<<endl;

		////////////////////////////////////////////////////////////
		//Decryption
		////////////////////////////////////////////////////////////

		ByteArray plaintextNew;

		std::cout << "\n" << "Running decryption..." << std::endl;

		//start = currentDateTime();

		DecodingResult result = algorithm.Decrypt(sk, ciphertext, &plaintextNew);  // This is the core decryption operation.

		//finish = currentDateTime();
		//diff = finish - start;

		//cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
		//fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

		cout << "\n" << "decrypted plaintext (NTRU encryption): " << plaintextNew << "\n" << endl;
		fout << "\n" << "decrypted plaintext (NTRU encryption): " << plaintextNew << "\n" << endl;

		if (!result.isValidCoding) {
			std::cout << "Decryption failed!" << std::endl;
			exit(1);
		}
		//PRE SCHEME

		//system("pause");

		LP_Algorithm_PRE_LWE_NTRU<ILVector2n, ILParams> algorithmPRE;

		////////////////////////////////////////////////////////////
		//Perform the second key generation operation.
		// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
		////////////////////////////////////////////////////////////

		LP_PublicKey_LWE_NTRU<ILVector2n, ILParams> newPK;
		LP_PrivateKey_LWE_NTRU<ILVector2n, ILParams> newSK;
		newSK.AccessCryptoParameters() = cryptoParams;
		newPK.AccessCryptoParameters() = cryptoParams;

		std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

		//start = currentDateTime();

		successKeyGen = algorithmPRE.KeyGen(newPK, newSK, dgg);	// This is the same core key generation operation.

		//finish = currentDateTime();
		//diff = finish - start;

		//cout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
		//fout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

		//	cout<<"newPK = "<<newPK.GetPublicElement().GetValues()<<endl;
		//	cout<<"newSK = "<<newSK.GetPrivateElement().GetValues()<<endl;
		//	fout<<"newPK = "<<newPK.GetPublicElement().GetValues()<<endl;
		//	fout<<"newSK = "<<newSK.GetPrivateElement().GetValues()<<endl;

		////////////////////////////////////////////////////////////
		//Perform the proxy re-encryption key generation operation.
		// This generates the keys which are used to perform the key switching.
		////////////////////////////////////////////////////////////

		std::cout << "\n" << "Generating proxy re-encryption key..." << std::endl;

		//start = currentDateTime();

		std::vector<ILVector2n> &proxyGen = algorithmPRE.ProxyGen(newPK, sk, dgg, relWindow);  // This is the core re-encryption operation.

		//finish = currentDateTime();
		//diff = finish - start;

		//cout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;
		//fout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;

		////////////////////////////////////////////////////////////
		//Perform the proxy re-encryption operation.
		// This switches the keys which are used to perform the key switching.
		////////////////////////////////////////////////////////////


		ILVector2n newCiphertext;

		std::cout << "\n" << "Running re-encryption..." << std::endl;

		//start = currentDateTime();

		algorithmPRE.ReEncrypt(proxyGen, cryptoParams, relWindow, ciphertext, &newCiphertext);  // This is the core re-encryption operation.

		//finish = currentDateTime();
		//diff = finish - start;

		//cout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
		//fout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

		//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

		////////////////////////////////////////////////////////////
		//Decryption
		////////////////////////////////////////////////////////////

		ByteArray plaintextNew2;

		std::cout << "\n" << "Running decryption of re-encrypted cipher..." << std::endl;

		//start = currentDateTime();

		DecodingResult result1 = algorithmPRE.Decrypt(newSK, newCiphertext, &plaintextNew2);  // This is the core decryption operation.

		//finish = currentDateTime();
		//diff = finish - start;

		//cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
		//fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

		cout << "\n" << "decrypted plaintext (PRE Re-Encrypt): " << plaintextNew2 << "\n" << endl;
		fout << "\n" << "decrypted plaintext (PRE Re-Encrypt): " << plaintextNew2 << "\n" << endl;

		if (!result1.isValidCoding) {
			std::cout << "Decryption failed!" << std::endl;
			exit(1);
		}

		std::cout << "Execution completed.  Please any key to finish." << std::endl;

		fout.close();

		delete &proxyGen;

		ChineseRemainderTransformFTT::GetInstance().Destroy();
		NumberTheoreticTransform::GetInstance().Destroy();

		ILVector2n::DestroyPreComputedSamples();

		//ILVector2n::PrintPreComputedSamples();
		
}
