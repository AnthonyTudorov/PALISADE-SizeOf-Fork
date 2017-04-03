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
		Jerry Ryan, gwryan@njit.edu
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
#include <iterator>
#include <chrono>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/byteplaintextencoding.h"
#include "utils/debug.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

void NTRUPRE(CryptoContext<ILVector2n>& ctx, string& parmset, bool dojson);

template<typename Element>
struct TestJsonParms {
	CryptoContext<Element>				ctx;
	shared_ptr<LPPublicKey<Element>>	pk;
	shared_ptr<LPPrivateKey<Element>>	sk;
	shared_ptr<LPEvalKey<Element>>		evalKey;
	shared_ptr<LPPrivateKey<Element>>	newSK;
};

template<typename Element> void testJson(const std::string cID, const BytePlaintextEncoding& newPtxt, TestJsonParms<Element> *p, bool skipReEncrypt = false);

template<typename Element>
void testJson(
		const std::string cID,
		const BytePlaintextEncoding& newPtxt,
		TestJsonParms<Element> *tp,
		bool skipReEncrypt) {

	shared_ptr<LPPublicKey<Element>>	pkDeserialized;
	shared_ptr<LPPrivateKey<Element>>	skDeserialized;
	shared_ptr<LPEvalKey<Element>>		evalKeyDeserialized;
	shared_ptr<LPPrivateKey<Element>>	newSKDeserialized;

	cout << "----------------------START JSON FACILITY TESTING-------------------------" << endl;

	size_t chunksize = newPtxt.GetChunksize(tp->ctx.GetCyclotomicOrder(), tp->ctx.GetCryptoParameters()->GetPlaintextModulus());
	if( newPtxt.size() > chunksize ) {
		cout << "This test code won't work when the plaintext size (" << newPtxt.size()
				<< ") is bigger than the chunksize (" << chunksize << ")" << endl;
		return;
	}

	string jsonFileName;
	string jsonRep;

	cout << "---BEGIN LPPublicKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap1;
	if (tp->pk->Serialize(&testMap1)) {
		jsonFileName = "LPPublicKey" + cID + "_Enc.txt";
		cout << "Saving to " << jsonFileName;
		if (SerializableHelper::WriteSerializationToFile(testMap1, jsonFileName))
			cout << " ... success!" << endl;
		else {
			cout << " ... failed!" << endl;
			return;
		}
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPPublicKey" + cID + " SERIALIZATION TESTING---" << endl << endl;

	cout << "---BEGIN LPPrivateKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap2;
	if (tp->sk->Serialize(&testMap2)) {
		jsonFileName = "LPPrivateKey" + cID + "_Enc.txt";
		cout << "Serialization saved to " << jsonFileName;
		if (SerializableHelper::WriteSerializationToFile(testMap2, jsonFileName))
			cout << " ... success!" << endl;
		else {
			cout << " ... failed!" << endl;
			return;
		}
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPPrivateKey" + cID + " SERIALIZATION---" << endl << endl;

	cout << "---BEGIN LPPublicKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPPublicKey" + cID + "_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, &testMap1);

	if ( pkDeserialized = tp->ctx.deserializePublicKey(testMap1) ) {
		cout << "Deserialized into pkDeserialized" << endl;
	} else {
		cout << "FAILED" << endl;
		return;
	}

	cout << "---END LPPublicKey" + cID + " DESERIALIZATION---" << endl << endl;

	cout << "---BEGIN LPPrivateKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPPrivateKey" + cID + "_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, &testMap2);
	if (skDeserialized = tp->ctx.deserializeSecretKey(testMap2) ) {
		cout << "Deserialized into skDeserialized" << endl;
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPPrivateKey" + cID + " DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithm" + cID + ".Encrypt TESTING----------" << endl;
	cout << "Calling Encrypt in LPAlgorithm" + cID + " with deserialized instance of LPPublicKey" + cID + "" << endl;
	vector<shared_ptr<Ciphertext<ILVector2n>>> testCiphertext;
	testCiphertext = tp->ctx.Encrypt(pkDeserialized, newPtxt);
	if( testCiphertext.size() == 0 ) {
		cout << "FAILED" << endl;
		return;
	}
	cout << "----------END LPAlgorithmPRE" + cID + ".Encrypt TESTING----------" << endl << endl;

	cout << "---BEGIN CIPHERTEXT SERIALIZATION---" << endl;
	cout << "Serializing testCiphertext object generated by Encrypt TESTING..." << endl;
	Serialized testMap3;
	if (testCiphertext[0]->Serialize(&testMap3)) {
		jsonFileName = "Ciphertext" + cID + "_Enc.txt";
		cout << "Serialization saved to " << jsonFileName;
		if (SerializableHelper::WriteSerializationToFile(testMap3, jsonFileName))
			cout << " ... success!" << endl;
		else {
			cout << " ... failed!" << endl;
			return;
		}
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END CIPHERTEXT SERIALIZATION---" << endl << endl;

	cout << "---BEGIN CIPHERTEXT DESERIALIZATION---" << endl;
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, &testMap3);
	shared_ptr<Ciphertext<Element>> ciphertextDeserialized;
	if (ciphertextDeserialized = tp->ctx.deserializeCiphertext(testMap3) )
		cout << "Deserialized into ciphertextDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END CIPHERTEXT DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithm" + cID + ".Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithm" + cID + " with deserialized instances of" << endl;
	cout << "LPPrivateKey" + cID + " and Ciphertext." << endl;
	BytePlaintextEncoding testPlaintextRec;
	vector<shared_ptr<Ciphertext<Element>>> ctDeser;
	ctDeser.push_back(ciphertextDeserialized);
	DecryptResult testResult = tp->ctx.Decrypt(skDeserialized, ctDeser, &testPlaintextRec);
	if( testResult.isValid == false ) {
		cout << "FAILED" << endl;
		return;
	}
	ctDeser.clear();

	cout << "Recovered plaintext from call to Decrypt: " << endl;
	cout << testPlaintextRec << endl;
	cout << "----------END LPAlgorithm" + cID + ".Decrypt TESTING----------" << endl << endl;

	if( skipReEncrypt )
		return;

	cout << "---BEGIN LPEvalKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap4;
	if (tp->evalKey->Serialize(&testMap4)) {
		jsonFileName = "LPEvalKey" + cID + "_Pre.txt";
		cout << "Saving serialization to " << jsonFileName;
		if (SerializableHelper::WriteSerializationToFile(testMap4, jsonFileName))
			cout << " ... success!" << endl;
		else {
			cout << " ... failed!" << endl;
			return;
		}
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPEvalKey" + cID + " SERIALIZATION TESTING---" << endl << endl;

	cout << "---BEGIN LPEvalKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPEvalKey" + cID + "_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, &testMap4);
	if( evalKeyDeserialized = tp->ctx.deserializeEvalKey(testMap4) )
		cout << "Deserialized into evalKeyDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPEvalKey" + cID + " DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithmPRE" + cID + ".ReEncrypt TESTING----------" << endl;
	cout << "Calling ReEncrypt in LPAlgorithmPRE" + cID + " with deserialized instances of" << endl;
	cout << "LPEvalKey" + cID + " and Ciphertext." << endl;

	vector<shared_ptr<Ciphertext<Element>>> ct;
	vector<shared_ptr<Ciphertext<Element>>> ctRe;
	ct.push_back(ciphertextDeserialized);

	shared_ptr<Ciphertext<Element>> preCiphertext;
	ctRe = tp->ctx.ReEncrypt(evalKeyDeserialized, ct);
	preCiphertext = ctRe[0];
	cout << "----------END LPAlgorithmPRE" + cID + ".ReEncrypt TESTING----------" << endl << endl;

	cout << "---BEGIN PRE LPPrivateKey" + cID + " SERIALIZATION---" << endl;
	cout << "Serializing previously used newSK object..." << endl;
	Serialized testMap5;
	if (tp->newSK->Serialize(&testMap5)) {
		jsonFileName = "LPPrivateKey" + cID + "_Pre.txt";
		cout << "Saving serialization to " << jsonFileName << endl;
		if (SerializableHelper::WriteSerializationToFile(testMap5, jsonFileName))
			cout << " ... success!" << endl;
		else {
			cout << " ... failed!" << endl;
			return;
		}
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END PRE LPPrivateKey" + cID + " SERIALIZATION---" << endl << endl;

	cout << "---BEGIN PRE CIPHERTEXT SERIALIZATION---" << endl;
	cout << "Serializing preCiphertext object generated by ReEncrypt TESTING..." << endl;
	Serialized testMap6;
	if (preCiphertext->Serialize(&testMap6)) {
		jsonFileName = "Ciphertext" + cID + "_Pre.txt";
		cout << "Saving serialization to " << jsonFileName << endl;
		if (SerializableHelper::WriteSerializationToFile(testMap6, jsonFileName))
			cout << " ... success!" << endl;
		else {
			cout << " ... failed!" << endl;
			return;
		}
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END PRE CIPHERTEXT SERIALIZATION---" << endl << endl;

	cout << "---BEGIN PRE LPPrivateKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPPrivateKey" + cID + "_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, &testMap5);
	if( newSKDeserialized = tp->ctx.deserializeSecretKey(testMap5) )
		cout << "Deserialized into newSKDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END PRE LPPrivateKey" + cID + " DESERIALIZATION---" << endl << endl;

	cout << "---BEGIN PRE CIPHERTEXT DESERIALIZATION---" << endl;
	jsonFileName = "Ciphertext" + cID + "_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, &testMap3);
	shared_ptr<Ciphertext<Element>> preCiphertextDeserialized;
	if( preCiphertextDeserialized = tp->ctx.deserializeCiphertext(testMap3) )
		cout << "Deserialized into preCiphertextDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END PRE CIPHERTEXT DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithmPRE" + cID + ".Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithmPRE" + cID + " with deserialized instances of" << endl;
	cout << "PRE LPPrivateKey" + cID + " and PRE Ciphertext." << endl;
	BytePlaintextEncoding testPlaintextPreRec;
	vector<shared_ptr<Ciphertext<Element>>> preCtVec;
	preCtVec.push_back(preCiphertextDeserialized);
	DecryptResult testResult1 = tp->ctx.Decrypt(newSKDeserialized, preCtVec, &testPlaintextPreRec);
	preCtVec.clear();

	cout << "Recovered plaintext from call to PRE Decrypt: " << endl;
	cout << testPlaintextPreRec << endl;
	cout << "----------END LPAlgorithmPRE" + cID + ".Decrypt TESTING----------" << endl << endl;
	std::cout
			<< "----------------------END JSON FACILITY TESTING-------------------------"
			<< endl << endl;
}


void usage()
{
	cout << "args are:" << endl;
	cout << "-dojson : includes the json tests" << endl;
}

int
main(int argc, char *argv[])
{
	bool	doJson = false;

	while( argc-- > 1 ) {
		string arg(*++argv);

		if( arg == "-dojson" )
			doJson = true;
		else if( arg == "-help" || arg == "-?" ) {
			usage();
			return 0;
		}
		else if( arg[0] == '-' ) {
			usage();
			return(0);
		}
	}

	std::cout << "Choose parameter set: ";
	CryptoContextHelper<ILVector2n>::printAllParmSetNames(std::cout);

	string input;
	std::cin >> input;

	CryptoContext<ILVector2n> ctx = CryptoContextHelper<ILVector2n>::getNewContext(input);
	if( !ctx ) {
		cout << "Error on " << input << endl;
		return 0;
	}

	ctx.Enable(ENCRYPTION);
	ctx.Enable(PRE);

	NTRUPRE(ctx, input, doJson);

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

void
NTRUPRE(CryptoContext<ILVector2n>& ctx, string& parmset, bool doJson) {

	BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");
	//BytePlaintextEncoding plaintext("NJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKLNJIT_CRYPTOGRAPHY_LABORATORY_IS_DEVELOPING_NEW-NTRU_LIKE_PROXY_REENCRYPTION_SCHEME_USING_LATTICE_BASED_CRYPTOGRAPHY_ABCDEFGHIJKL");


	ofstream fout;
	fout.open ("output.txt");


	std::cout << " \nCryptosystem initialization: Performing precomputations..." << std::endl;

	double diff, start, finish;

	start = currentDateTime();

	//This code is run only when performing execution time measurements

	try {
		//Precomputations for TUG
		ILVector2n::PreComputeTugSamples(GeneratorContainer<BigBinaryInteger,BigBinaryVector>::GetGenerator(TernaryUniformGen), ctx.GetElementParams());
	} catch (...) {
		// ignore if this fails... which it will in some cases, like if there is no generator in use
	}

	finish = currentDateTime();
	diff = finish - start;

	cout << "Precomputation time: " << "\t" << diff << " ms" << endl;
	fout << "Precomputation time: " << "\t" << diff << " ms" << endl;

	//Regular LWE-NTRU encryption algorithm

	////////////////////////////////////////////////////////////
	//Perform the key generation operation.
	////////////////////////////////////////////////////////////

	std::cout <<"\n" <<  "Running key generation..." << std::endl;

	start = currentDateTime();

	LPKeyPair<ILVector2n> kp = ctx.KeyGen();	// This is the core function call that generates the keys.

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	//fout<< currentDateTime()  << " pk = "<<pk.GetPublicElement().GetValues()<<endl;
	//fout<< currentDateTime()  << " sk = "<<sk.GetPrivateElement().GetValues()<<endl;

	if (!kp.good()) {
		std::cout<<"Key generation failed!"<<std::endl;
		exit(1);
	}

	////////////////////////////////////////////////////////////
	//Encryption
	////////////////////////////////////////////////////////////

	// Begin the initial encryption operation.
	cout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;
	fout<<"\n"<<"original plaintext: "<<plaintext<<"\n"<<endl;

	vector<shared_ptr<Ciphertext<ILVector2n>>> ciphertext;

	std::cout << "Running encryption..." << std::endl;

	start = currentDateTime();

	ciphertext = ctx.Encrypt(kp.publicKey,plaintext);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew;

	std::cout <<"\n"<< "Running decryption..." << std::endl;

	start = currentDateTime();

	DecryptResult result = ctx.Decrypt(kp.secretKey,ciphertext,&plaintextNew);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (NTRU encryption): "<<plaintextNew<<"\n"<<endl;

	//cout << "ciphertext at" << ciphertext.GetIndexAt(2);

	if (!result.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	//PRE SCHEME

	////////////////////////////////////////////////////////////
	//Perform the second key generation operation.
	// This generates the keys which should be able to decrypt the ciphertext after the re-encryption operation.
	////////////////////////////////////////////////////////////

	std::cout << "Running second key generation (used for re-encryption)..." << std::endl;

	start = currentDateTime();

	LPKeyPair<ILVector2n> newKp = ctx.KeyGen();	// This is the same core key generation operation.

	finish = currentDateTime();
	diff = finish - start;

	cout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout << "Key generation execution time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption key generation operation.
	// This generates the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////

	std::cout <<"\n"<< "Generating proxy re-encryption key..." << std::endl;

	shared_ptr<LPEvalKey<ILVector2n>> evalKey;

	try {

	start = currentDateTime();

	evalKey = ctx.ReKeyGen(newKp.publicKey, kp.secretKey);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption key generation time: "<<"\t"<<diff<<" ms"<<endl;

	////////////////////////////////////////////////////////////
	//Perform the proxy re-encryption operation.
	// This switches the keys which are used to perform the key switching.
	////////////////////////////////////////////////////////////


	vector<shared_ptr<Ciphertext<ILVector2n>>> newCiphertext;

	std::cout <<"\n"<< "Running re-encryption..." << std::endl;

	start = currentDateTime();

	newCiphertext = ctx.ReEncrypt(evalKey, ciphertext);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Re-encryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	//cout<<"new CipherText - PRE = "<<newCiphertext.GetValues()<<endl;

	////////////////////////////////////////////////////////////
	//Decryption
	////////////////////////////////////////////////////////////

	BytePlaintextEncoding plaintextNew2;

	std::cout <<"\n"<< "Running decryption of re-encrypted cipher..." << std::endl;

	start = currentDateTime();

	DecryptResult result1 = ctx.Decrypt(newKp.secretKey,newCiphertext,&plaintextNew2);

	finish = currentDateTime();
	diff = finish - start;

	cout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;
	fout<< "Decryption execution time: "<<"\t"<<diff<<" ms"<<endl;

	cout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;
	fout<<"\n"<<"decrypted plaintext (PRE Re-Encrypt): "<<plaintextNew2<<"\n"<<endl;

	if (!result1.isValid) {
		std::cout<<"Decryption failed!"<<std::endl;
		exit(1);
	}

	std::cout << "Execution completed." << std::endl;
	} catch (const exception& e) {
		cout << "Re Encryption threw exception: " << e.what() << endl;
	}

	BytePlaintextEncoding newPlaintext("1) SERIALIZE CRYPTO-OBJS TO FILE AS NESTED JSON STRUCTURES\n2) DESERIALIZE JSON FILES INTO CRYPTO-OBJS USED FOR CRYPTO-APIS\n3) Profit!!!!!");

	cout << "Original Plaintext: " << endl;
	cout << newPlaintext << endl;

	if( doJson ) {
		TestJsonParms<ILVector2n>	tjp;
		tjp.ctx = ctx;
		tjp.pk = kp.publicKey;
		tjp.sk = kp.secretKey;
		tjp.evalKey = evalKey;
		tjp.newSK = newKp.secretKey;

		testJson<ILVector2n>(parmset, newPlaintext, &tjp, !evalKey ? true: false);
	}

	fout.close();
}


