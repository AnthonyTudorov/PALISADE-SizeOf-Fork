/*
 * testJson.cpp
 *
 *  Created on: May 22, 2016
 *      Author: gerardryan
 */

#include <iostream>
#include <fstream>
#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/encoding/byteencoding.h"
#include "../../lib/encoding/cryptoutility.h"
#include "../../lib/utils/debug.h"

#include <chrono>

#include "../../lib/utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

#include "testJson.h"

void testJson(
		const std::string cID,
		const ByteArray& newPtxt,
		TestJsonParms *tp) {

	LPPublicKeyLTV<ILVector2n>				pkDeserialized;
	LPPrivateKeyLTV<ILVector2n>				skDeserialized;
	LPEvalKeyLTV<ILVector2n>				evalKeyDeserialized;
	LPPrivateKeyLTV<ILVector2n>				newSKDeserialized;

	std::cout << "----------------------START JSON FACILITY TESTING-------------------------" << endl;

	string jsonFileName;
	string jsonRep;

	cout << "---BEGIN LPPublicKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap1;
	if (tp->pk->Serialize(&testMap1, "Enc")) {
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
	if (tp->sk->Serialize(&testMap2, "Enc")) {
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

	if (pkDeserialized.Deserialize(testMap1, tp->ctx)) {
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
	if (skDeserialized.Deserialize(testMap2, tp->ctx)) {
		cout << "Deserialized into skDeserialized" << endl;
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPPrivateKey" + cID + " DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithm" + cID + ".Encrypt TESTING----------" << endl;
	cout << "Calling Encrypt in LPAlgorithm" + cID + " with deserialized instance of LPPublicKey" + cID + "" << endl;
	vector<Ciphertext<ILVector2n>> testCiphertext;
	EncryptResult er = CryptoUtility<ILVector2n>::Encrypt(*tp->ctx->getAlgorithm(), pkDeserialized, newPtxt, &testCiphertext);
	if( er.isValid == false ) {
		cout << "FAILED" << endl;
		return;
	}
	cout << "----------END LPAlgorithmPRE" + cID + ".Encrypt TESTING----------" << endl << endl;

	cout << "---BEGIN CIPHERTEXT SERIALIZATION---" << endl;
	cout << "Serializing testCiphertext object generated by Encrypt TESTING..." << endl;
	Serialized testMap3;
	if (testCiphertext[0].Serialize(&testMap3, "Enc")) {
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
	Ciphertext<ILVector2n> ciphertextDeserialized;
	if (ciphertextDeserialized.Deserialize(testMap3, tp->ctx))
		cout << "Deserialized into ciphertextDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END CIPHERTEXT DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithm" + cID + ".Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithm" + cID + " with deserialized instances of" << endl;
	cout << "LPPrivateKey" + cID + " and Ciphertext." << endl;
	ByteArray testPlaintextRec;
	vector<Ciphertext<ILVector2n>> ctDeser;
	ctDeser.push_back(ciphertextDeserialized);
	DecryptResult testResult = CryptoUtility<ILVector2n>::Decrypt(*tp->ctx->getAlgorithm(), skDeserialized,
			ctDeser, &testPlaintextRec);
	if( testResult.isValid == false ) {
		cout << "FAILED" << endl;
		return;
	}
	ctDeser.clear();

	cout << "Recovered plaintext from call to Decrypt: " << endl;
	cout << testPlaintextRec << endl;
	cout << "----------END LPAlgorithm" + cID + ".Decrypt TESTING----------" << endl << endl;

	cout << "---BEGIN LPEvalKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap4;
	if (tp->evalKey->Serialize(&testMap4, "Pre")) {
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
	if( evalKeyDeserialized.Deserialize(testMap4, tp->ctx) )
		cout << "Deserialized into evalKeyDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPEvalKey" + cID + " DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithmPRE" + cID + ".ReEncrypt TESTING----------" << endl;
	cout << "Calling ReEncrypt in LPAlgorithmPRE" + cID + " with deserialized instances of" << endl;
	cout << "LPEvalKey" + cID + " and Ciphertext." << endl;

	vector<Ciphertext<ILVector2n>> ct;
	vector<Ciphertext<ILVector2n>> ctRe;
	ct.push_back(ciphertextDeserialized);

	Ciphertext<ILVector2n> preCiphertext;
	CryptoUtility<ILVector2n>::ReEncrypt(*tp->ctx->getAlgorithm(), evalKeyDeserialized, ct, &ctRe);
	preCiphertext = ctRe[0];
	cout << "----------END LPAlgorithmPRE" + cID + ".ReEncrypt TESTING----------" << endl << endl;

	cout << "---BEGIN PRE LPPrivateKey" + cID + " SERIALIZATION---" << endl;
	cout << "Serializing previously used newSK object..." << endl;
	Serialized testMap5;
	if (tp->newSK->Serialize(&testMap5, "Pre")) {
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
	if (preCiphertext.Serialize(&testMap6, "Pre")) {
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
	if( newSKDeserialized.Deserialize(testMap5, tp->ctx) )
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
	Ciphertext<ILVector2n> preCiphertextDeserialized;
	if( preCiphertextDeserialized.Deserialize(testMap3, tp->ctx) )
		cout << "Deserialized into preCiphertextDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END PRE CIPHERTEXT DESERIALIZATION---" << endl << endl;

	cout << "----------BEGIN LPAlgorithmPRE" + cID + ".Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithmPRE" + cID + " with deserialized instances of" << endl;
	cout << "PRE LPPrivateKey" + cID + " and PRE Ciphertext." << endl;
	ByteArray testPlaintextPreRec;
	vector<Ciphertext<ILVector2n>> preCtVec;
	preCtVec.push_back(preCiphertextDeserialized);
	DecryptResult testResult1 = CryptoUtility<ILVector2n>::Decrypt(*tp->ctx->getAlgorithm(), newSKDeserialized,
			preCtVec, &testPlaintextPreRec);
	preCtVec.clear();

	cout << "Recovered plaintext from call to PRE Decrypt: " << endl;
	cout << testPlaintextPreRec << endl;
	cout << "----------END LPAlgorithmPRE" + cID + ".Decrypt TESTING----------" << endl << endl;
	std::cout
			<< "----------------------END JSON FACILITY TESTING-------------------------"
			<< endl << endl;
}


