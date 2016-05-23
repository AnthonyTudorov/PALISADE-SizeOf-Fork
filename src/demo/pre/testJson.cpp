/*
 * testJson.cpp
 *
 *  Created on: May 22, 2016
 *      Author: gerardryan
 */

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
//#include "../../lib/time.h"

#include "../../lib/utils/debug.h"
#include "../../lib/crypto/ciphertext.cpp"
//#include "../../lib/vld.h"
#include <chrono>
//#include "../../lib/gtest/gtest.h"
//#include "../../lib/math/cpu8bit/binint.h"
//#include "../../lib/math/cpu8bit/binvect.h"
//#include "../../lib/math/cpu8bit/binmat.h"

#include "../../lib/utils/serializablehelper.h"

#include "../../lib/encoding/ptxtencoding.h"

using namespace std;
using namespace lbcrypto;


void testJson(
		const std::string cID,
		const LPPublicKey<ILVector2n>& pk,
		const LPPrivateKey<ILVector2n>& sk,
		const LPPublicKeyEncryptionScheme<ILVector2n>& algorithm,
		const LPEvalKey<ILVector2n>& evalKey,
		const LPPrivateKey<ILVector2n>& newSK,
		const ByteArrayPlaintextEncoding& newPtxt) {

	std::cout << "----------------------START JSON FACILITY TESTING-------------------------" << endl;

	string jsonFileName;
	string jsonRep;

	cout << "---BEGIN LPPublicKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap1;
	if (pk.Serialize(testMap1, "Enc")) {
		cout << "encoded" << endl;
//		for( Serialized::ConstMemberIterator it = testMap1.MemberBegin() ; it != testMap1.MemberEnd(); ++it ) {
//			cout << it->name.GetString() << endl;
//			for( Serialized::ConstMemberIterator sit = it->value.MemberBegin() ; sit != it->value.MemberEnd(); ++sit ) {
//				cout << " " << sit->name.GetString() <<endl;
//				if( sit->value.IsObject() ) {
//					for( Serialized::ConstMemberIterator thit = sit->value.MemberBegin() ; thit != sit->value.MemberEnd(); ++thit ) {
//						cout << "    " << thit->name.GetString() <<endl;
//					}
//				}
//			}
//		}
//		SerializableHelper::SerializationToString(testMap1, jsonRep);
//		cout << jsonRep << endl;
		jsonFileName = "LPPublicKey" + cID + "_Enc.txt";
		cout << "Saving to " << jsonFileName <<endl;
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
	cout << "---END LPPublicKey" + cID + " SERIALIZATION TESTING---" << endl;

	cout << "---BEGIN LPPrivateKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap2;
	if (sk.Serialize(testMap2, "Enc")) {
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
	cout << "---END LPPrivateKey" + cID + " SERIALIZATION---" << endl;

	cout << "---BEGIN LPPublicKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPPublicKey" + cID + "_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, testMap1);
	LPPublicKeyLTV<ILVector2n> pkDeserialized;
	LPCryptoParametersLTV<ILVector2n> json_cryptoParamsPub;
	pkDeserialized.SetCryptoParameters(&json_cryptoParamsPub);
	if (pkDeserialized.Deserialize(testMap1)) {
		cout << "Deserialized into pkDeserialized" << endl;
	} else {
		cout << "FAILED" << endl;
		return;
	}

	cout << "---END LPPublicKey" + cID + " DESERIALIZATION---" << endl;

	cout << "---BEGIN LPPrivateKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPPrivateKey" + cID + "_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, testMap2);
	LPPrivateKeyLTV<ILVector2n> skDeserialized;
	LPCryptoParametersLTV<ILVector2n> json_cryptoParamsPriv;
	skDeserialized.SetCryptoParameters(&json_cryptoParamsPriv);
	if (skDeserialized.Deserialize(testMap2)) {
		cout << "Deserialized into skDeserialized" << endl;
	} else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPPrivateKey" + cID + " DESERIALIZATION---" << endl;

	cout << "\n" << endl;
	cout << "----------BEGIN LPAlgorithm" + cID + ".Ecrypt TESTING----------" << endl;
	cout << "Calling Encrypt in LPAlgorithm" + cID + " with deserialized instance of LPPublicKey" + cID + "" << endl;
	Ciphertext<ILVector2n> testCiphertext;
	algorithm.Encrypt(pkDeserialized, newPtxt, &testCiphertext);
	cout << "----------END LPAlgorithmPRE" + cID + ".ReEcrypt TESTING----------" << endl;

	cout << "\n" << endl;
	cout << "---BEGIN CIPHERTEXT SERIALIZATION---" << endl;
	cout << "Serializing testCiphertext object generated by Encrypt TESTING..." << endl;
	Serialized testMap3;
	if (testCiphertext.Serialize(testMap3, "Enc")) {
		jsonFileName = "Ciphertext_Enc.txt";
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
	cout << "---END CIPHERTEXT SERIALIZATION---" << endl;

	cout << "---BEGIN CIPHERTEXT DESERIALIZATION---" << endl;
	jsonFileName = "Ciphertext_Enc.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, testMap3);
	Ciphertext<ILVector2n> ciphertextDeserialized;
	if (ciphertextDeserialized.Deserialize(testMap3))
		cout << "Deserialized into ciphertextDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}

	cout << "---END CIPHERTEXT DESERIALIZATION---" << endl;

	cout << "\n" << endl;
	cout << "----------BEGIN LPAlgorithm" + cID + ".Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithm" + cID + " with deserialized instances of" << endl;
	cout << "LPPrivateKey" + cID + " and Ciphertext." << endl;
	ByteArrayPlaintextEncoding testPlaintextRec;
	DecodingResult testResult = algorithm.Decrypt(skDeserialized,
			ciphertextDeserialized, &testPlaintextRec);
	testPlaintextRec.Unpad<ZeroPad>();
	cout << "Recovered plaintext from call to Decrypt: " << endl;
	cout << testPlaintextRec << endl;
	cout << "----------END LPAlgorithm" + cID + ".Decrypt TESTING----------" << endl;

	cout << "\n" << endl;
	cout << "---BEGIN LPEvalKey" + cID + " SERIALIZATION---" << endl;
	Serialized testMap4;
	if (evalKey.Serialize(testMap4, "Pre")) {
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
	cout << "---END LPEvalKey" + cID + " SERIALIZATION TESTING---" << endl;
	cout << "---BEGIN LPEvalKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPEvalKey" + cID + "_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, testMap4);
	LPEvalKeyLTV<ILVector2n> evalKeyDeserialized;
	LPCryptoParametersLTV<ILVector2n> json_cryptoParamsEval;
	evalKeyDeserialized.SetCryptoParameters(&json_cryptoParamsEval);
	if( evalKeyDeserialized.Deserialize(testMap4) )
		cout << "Deserialized into evalKeyDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END LPEvalKey" + cID + " DESERIALIZATION---" << endl;

	cout << "\n" << endl;
	cout << "----------BEGIN LPAlgorithmPRE" + cID + ".ReEcrypt TESTING----------"
			<< endl;
	cout
			<< "Calling ReEncrypt in LPAlgorithmPRE" + cID + " with deserialized instances of"
			<< endl;
	cout << "LPEvalKey" + cID + " and Ciphertext." << endl;
	Ciphertext<ILVector2n> preCiphertext;
	algorithm.ReEncrypt(evalKeyDeserialized, ciphertextDeserialized,
			&preCiphertext);
	cout << "----------END LPAlgorithmPRE" + cID + ".ReEcrypt TESTING----------" << endl;

	cout << "\n" << endl;
	cout << "---BEGIN PRE LPPrivateKey" + cID + " SERIALIZATION---" << endl;
	cout << "Serializing previously used newSK object..." << endl;
	Serialized testMap5;
	if (newSK.Serialize(testMap5, "Pre")) {
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
	cout << "---END PRE LPPrivateKey" + cID + " SERIALIZATION---" << endl;
	cout << "---BEGIN PRE CIPHERTEXT SERIALIZATION---" << endl;
	cout << "Serializing preCiphertext object generated by ReEncrypt TESTING..." << endl;
	Serialized testMap6;
	if (preCiphertext.Serialize(testMap6, "Pre")) {
		jsonFileName = "Ciphertext_Pre.txt";
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
	cout << "---END PRE CIPHERTEXT SERIALIZATION---" << endl;

	cout << "---BEGIN PRE LPPrivateKey" + cID + " DESERIALIZATION---" << endl;
	jsonFileName = "LPPrivateKey" + cID + "_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, testMap5);
	LPPrivateKeyLTV<ILVector2n> newSKDeserialized;
	LPCryptoParametersLTV<ILVector2n> json_cryptoParamsNewPriv;
	newSKDeserialized.SetCryptoParameters(&json_cryptoParamsNewPriv);
	if( newSKDeserialized.Deserialize(testMap5) )
		cout << "Deserialized into newSKDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END PRE LPPrivateKey" + cID + " DESERIALIZATION---" << endl;

	cout << "---BEGIN PRE CIPHERTEXT DESERIALIZATION---" << endl;
	jsonFileName = "Ciphertext_Pre.txt";
	cout << "Deserializing instance from " << jsonFileName << endl;
	SerializableHelper::ReadSerializationFromFile(jsonFileName, testMap3);
	Ciphertext<ILVector2n> preCiphertextDeserialized;
	if( preCiphertextDeserialized.Deserialize(testMap3) )
		cout << "Deserialized into preCiphertextDeserialized" << endl;
	else {
		cout << "FAILED" << endl;
		return;
	}
	cout << "---END PRE CIPHERTEXT DESERIALIZATION---" << endl;

	cout << "\n" << endl;
	cout << "----------BEGIN LPAlgorithmPRE" + cID + ".Decrypt TESTING----------" << endl;
	cout << "Calling Decrypt in LPAlgorithmPRE" + cID + " with deserialized instances of" << endl;
	cout << "PRE LPPrivateKey" + cID + " and PRE Ciphertext." << endl;
	ByteArrayPlaintextEncoding testPlaintextPreRec;
	DecodingResult testResult1 = algorithm.Decrypt(newSKDeserialized,
			preCiphertextDeserialized, &testPlaintextPreRec);
	testPlaintextPreRec.Unpad<ZeroPad>();
	cout << "Recovered plaintext from call to PRE Decrypt: " << endl;
	cout << testPlaintextPreRec << endl;
	cout << "----------END LPAlgorithmPRE" + cID + ".Decrypt TESTING----------" << endl;
	cout << "\n" << endl;
	std::cout
			<< "----------------------END JSON FACILITY TESTING-------------------------"
			<< endl;
	cout << "\n" << endl;
}


