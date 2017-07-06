/*
 * PalisadeCrypto.cpp
 *
 *  Created on: May 26, 2016
 *      Author: gwryan
 */

#include "com_palisade_PalisadeCrypto.h"

#include <string>
#include <memory>

#include <iostream>
#include <fstream>
#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/serializablehelper.h"
#include "../../lib/encoding/byteplaintextencoding.h"

using namespace std;
using namespace lbcrypto;

class JavaPalisadeCrypto {
public:
	CryptoContext<Poly>				ctx;
	string									errorMessage;
	shared_ptr<LPPublicKey<Poly>>		publicKey;
	shared_ptr<LPPrivateKey<Poly>>	secretKey;
	shared_ptr<LPEvalKey<Poly>>		evalKey;

	JavaPalisadeCrypto(const CryptoContext<Poly>& ctx) : ctx(ctx), errorMessage("") {}
};

static JavaPalisadeCrypto* getCrypto(JNIEnv *env, jobject thiz)
{
	// find the getObject method
	jclass pCrypto = env->FindClass("com/palisade/PalisadeCrypto");
	if( pCrypto == 0 ) return 0;
	jmethodID getId = env->GetMethodID(pCrypto, "getObject", "()J");
	if( getId == 0 ) return 0;
	jlong objptr = env->CallLongMethod(thiz, getId);

	return (JavaPalisadeCrypto *)objptr;
}


/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    getPalisadeKeyPair
 * Signature: (Ljava/lang/String;)Lcom/palisade/PalisadeKeypair;
 */
JNIEXPORT jobject JNICALL Java_com_palisade_PalisadeCrypto_generatePalisadeKeyPair
(JNIEnv *env, jobject thiz)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	LPKeyPair<Poly> kp = cp->ctx.KeyGen();

	if( !kp.good() )
		return 0;

	Serialized pubMap, priMap;
	string	pubStr, priStr;

	if ( !kp.publicKey->Serialize(&pubMap) || !kp.secretKey->Serialize(&priMap) ) {
		return 0;
	}

	if( !SerializableHelper::SerializationToString(pubMap, pubStr) || !SerializableHelper::SerializationToString(priMap, priStr) )
		return 0;

	jbyteArray pubA = env->NewByteArray(pubStr.length());
	env->SetByteArrayRegion(pubA, 0, pubStr.length(), (jbyte *)pubStr.c_str());

	jbyteArray priA = env->NewByteArray(priStr.length());
	env->SetByteArrayRegion(priA, 0, priStr.length(), (jbyte *)priStr.c_str());

	jvalue ctorargs[2];
	ctorargs[0].l = pubA;
	ctorargs[1].l = priA;

	jclass pKeypair = env->FindClass("com/palisade/PalisadeKeypair");
	jmethodID ctor = env->GetMethodID(pKeypair, "<init>", "([B[B)V");
	jobject kpair = env->NewObjectA(pKeypair, ctor, ctorargs);

	return kpair;
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPublicKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return false;

	jboolean isCopy;
	char *kData = (char *)env->GetByteArrayElements(key, &isCopy);
	string keyStr(kData, env->GetArrayLength(key));
	if( isCopy ) env->ReleaseByteArrayElements(key, (jbyte *)kData, JNI_ABORT);

	Serialized serObj;
	SerializableHelper::StringToSerialization(keyStr, &serObj);

	cp->publicKey = cp->ctx.deserializePublicKey(serObj);

	return cp->publicKey != NULL;
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPrivateKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return false;

	jboolean isCopy;
	char *kData = (char *)env->GetByteArrayElements(key, &isCopy);
	string keyStr(kData, env->GetArrayLength(key));
	if( isCopy ) env->ReleaseByteArrayElements(key, (jbyte *)kData, JNI_ABORT);

	Serialized serObj;
	SerializableHelper::StringToSerialization(keyStr, &serObj);

	cp->secretKey = cp->ctx.deserializeSecretKey(serObj);

	return cp->secretKey != NULL;
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setEvalKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return false;

	jboolean isCopy;
	char *kData = (char *)env->GetByteArrayElements(key, &isCopy);
	string keyStr(kData, env->GetArrayLength(key));
	if( isCopy ) env->ReleaseByteArrayElements(key, (jbyte *)kData, JNI_ABORT);

	Serialized serObj;
	SerializableHelper::StringToSerialization(keyStr, &serObj);

	cp->evalKey = cp->ctx.deserializeEvalKey(serObj);

	return cp->evalKey != NULL;
}

JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_getPalisadeErrorDescription
(JNIEnv *env, jobject thiz)
{
	string errorMessage;

	JavaPalisadeCrypto* cp = getCrypto(env, thiz);

	if( cp == 0 ) {
		errorMessage = "No Internal Java Crypto Context is available";
	}
	else {
		errorMessage = cp->errorMessage;
	}

	int byteCount = errorMessage.length();
	jbyte *pNativeMsg = const_cast<jbyte *>( reinterpret_cast<const jbyte *>(errorMessage.c_str()) );
	jbyteArray bytes = env->NewByteArray(byteCount);
	env->SetByteArrayRegion(bytes, 0, byteCount, pNativeMsg);

	return bytes;
}

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    getPalisadeEvalKey
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_generatePalisadeEvalKey
(JNIEnv *env, jobject thiz, jbyteArray pub, jbyteArray pri)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) {
		return 0;
	}

	if( pub == 0 ) {
		cp->errorMessage = "No public key provided to generateEvalKey";
		return 0;
	}

	if( pri == 0 ) {
		cp->errorMessage = "No private key provided to generateEvalKey";
		return 0;
	}

	jboolean isCopy, isCopy2;
	char *pData = (char *)env->GetByteArrayElements(pub, &isCopy);
	string pubKstr(pData, env->GetArrayLength(pub));
	char *sData = (char *)env->GetByteArrayElements(pri, &isCopy2);
	string priKstr(sData, env->GetArrayLength(pri));

	if( isCopy ) env->ReleaseByteArrayElements(pub, (jbyte *)pData, JNI_ABORT);
	if( isCopy2 ) env->ReleaseByteArrayElements(pri, (jbyte *)sData, JNI_ABORT);

	// deserialize the keys

	shared_ptr<LPPublicKey<Poly>> pk;
	shared_ptr<LPPrivateKey<Poly>> sk;

	Serialized pkS, skS;
	if( !SerializableHelper::StringToSerialization(pubKstr, &pkS) ) {
		cp->errorMessage = "Unable to convert public key to JSON document in generateEvalKey";
		return 0;
	}

	if( !SerializableHelper::StringToSerialization(priKstr, &skS) ) {
		cp->errorMessage = "Unable to convert private key to JSON document in generateEvalKey";
		return 0;
	}

	if( (pk = cp->ctx.deserializePublicKey(pkS)) == NULL ) {
		cp->errorMessage = "Unable to deserialize public key in generateEvalKey";
		return 0;
	}
	if( (sk = cp->ctx.deserializeSecretKey(skS)) == NULL ) {
		cp->errorMessage = "Unable to deserialize private key in generateEvalKey";
		return 0;
	}

	shared_ptr<LPEvalKey<Poly>> evalKey = cp->ctx.ReKeyGen(pk, sk);
	if( evalKey == NULL ) {
		cp->errorMessage = "ReKeyGen failed in generateEvalKey";
		return 0;
	}

	Serialized ekS;
	string	ekStr;

	if ( !evalKey->Serialize(&ekS) ) {
		cp->errorMessage = "Unable to serialize eval key in generateEvalKey";
		return 0;
	}

	if( !SerializableHelper::SerializationToString(ekS, ekStr) ) {
		cp->errorMessage = "Unable to convert serialized eval key to JSON string in generateEvalKey";
		return 0;
	}

	jbyteArray evA = env->NewByteArray(ekStr.length());
	env->SetByteArrayRegion(evA, 0, ekStr.length(), (jbyte *)ekStr.c_str());

	return evA;
}

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    encrypt
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_encrypt
(JNIEnv *env, jobject thiz, jbyteArray cleartext)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	if( cleartext == 0 ) {
		cp->errorMessage = "No cleartext was provided to encrypt";
		return 0;
	}

	jboolean isCopy;
	char *clearData = (char *)env->GetByteArrayElements(cleartext, &isCopy);
	long totalBytes = env->GetArrayLength(cleartext);

	BytePlaintextEncoding ptxt(clearData);

	string totalSer = "";

	vector<shared_ptr<Ciphertext<Poly>>> ciphertext = cp->ctx.Encrypt(cp->publicKey, ptxt, true);

	for( int i=0; i<ciphertext.size(); i++ ) {
		Serialized txtS;
		string	txtSer;

		if ( !ciphertext[i]->Serialize(&txtS) )
			break;
		if( !SerializableHelper::SerializationToString(txtS, txtSer) )
			break;
		totalSer += txtSer + "$";
	}

	jbyteArray evA = 0;

	evA = env->NewByteArray(totalSer.length());
	env->SetByteArrayRegion(evA, 0, totalSer.length(), (jbyte *)totalSer.c_str());

	if( isCopy ) env->ReleaseByteArrayElements(cleartext, (jbyte *)clearData, JNI_ABORT);

	return evA;
}

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    reEncrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_reEncrypt
(JNIEnv *env, jobject thiz, jbyteArray enctext)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	jboolean isCopy;
	char *encData = (char *)env->GetByteArrayElements(enctext, &isCopy);
	usint encBytes = env->GetArrayLength(enctext);
	char *bufp = encData;

	// deserialize the enc test

	if( cp->evalKey == 0 ) return 0;

	shared_ptr<Ciphertext<Poly>> ciphertext;
	vector<shared_ptr<Ciphertext<Poly>>> cipherVec;

	string chunkStr;
	string result = "";
	do {
		chunkStr = "";
		while( encBytes > 0 && *bufp != '$' ) {
			chunkStr += *bufp++;
			encBytes--;
		}

		bufp++;
		encBytes--;

		Serialized kD;
		if( !SerializableHelper::StringToSerialization(chunkStr, &kD) )
			break;

		if( (ciphertext = cp->ctx.deserializeCiphertext(kD)) == 0 )
			break;

		cipherVec.push_back(ciphertext);
	} while( encBytes > 0 );

	vector<shared_ptr<Ciphertext<Poly>>> newCiphertext = cp->ctx.ReEncrypt(cp->evalKey,cipherVec);

	for( int i=0; i<newCiphertext.size(); i++ ) {

		Serialized txtS;
		string	txtSer;

		if ( !newCiphertext[i]->Serialize(&txtS) ) {
			break;
		}

		if( !SerializableHelper::SerializationToString(txtS, txtSer) ) {
			break;
		}

		result += txtSer + "$";
	}

	jbyteArray evA = 0;
	evA = env->NewByteArray(result.length());
	env->SetByteArrayRegion(evA, 0, result.length(), (jbyte *)result.c_str());

	if( isCopy ) env->ReleaseByteArrayElements(enctext, (jbyte *)encData, JNI_ABORT);
	return evA;
}

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    decrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_decrypt
(JNIEnv *env, jobject thiz, jbyteArray enctext)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	jboolean isCopy;
	char *encData = (char *)env->GetByteArrayElements(enctext, &isCopy);
	usint encBytes = env->GetArrayLength(enctext);
	char *bufp = encData;

	// deserialize the enc text

	if( cp->secretKey == 0 ) return 0;

	shared_ptr<Ciphertext<Poly>> ciphertext;
	vector<shared_ptr<Ciphertext<Poly>>> cipherVec;
	BytePlaintextEncoding plaintext;

	string chunkStr;
	string result = "";
	do {
		chunkStr = "";
		while( encBytes > 0 && *bufp != '$' ) {
			chunkStr += *bufp++;
			encBytes--;
		}

		bufp++;
		encBytes--;

		Serialized kD;
		if( !SerializableHelper::StringToSerialization(chunkStr, &kD) )
			break;

		if( (ciphertext = cp->ctx.deserializeCiphertext(kD)) == 0 )
			break;

		cipherVec.push_back(ciphertext);
	} while( encBytes > 0 );

	DecryptResult result1 = cp->ctx.Decrypt(cp->secretKey, cipherVec, &plaintext);

	std::cout << plaintext.size() << std::endl;
	string ptStr(plaintext.begin(), plaintext.end());
	std::cout << ptStr.length() << std::endl;

	jbyteArray evA = 0;
	evA = env->NewByteArray(ptStr.length());
	env->SetByteArrayRegion(evA, 0, ptStr.length(), (jbyte *)ptStr.c_str());

	if( isCopy ) env->ReleaseByteArrayElements(enctext, (jbyte *)encData, JNI_ABORT);
	return evA;
}


/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    openPalisadeCrypto
 * Signature: ()V
 */
JNIEXPORT jlong JNICALL Java_com_palisade_PalisadeCrypto_openPalisadeCrypto
(JNIEnv *env, jobject thiz, jbyteArray parmJson)
{

	jboolean isCopy;
	char *parms = (char *)env->GetByteArrayElements(parmJson, &isCopy);

	string cp(parms, env->GetArrayLength(parmJson));
	if( isCopy ) env->ReleaseByteArrayElements(parmJson, (jbyte *)parms, JNI_ABORT);

	CryptoContext<Poly> ctx = CryptoContextHelper::getNewContext( cp );

	if( bool(ctx) == false ) {
		return 0;
	}

	ctx.Enable(ENCRYPTION);
	ctx.Enable(PRE);

	JavaPalisadeCrypto	*cparms = new JavaPalisadeCrypto(ctx);
	return (jlong)cparms;
}

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    closePalisadeCrypto
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_palisade_PalisadeCrypto_closePalisadeCrypto
(JNIEnv *env, jobject thiz)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);

	delete cp;
}
