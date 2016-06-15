/*
 * PalisadeCrypto.cpp
 *
 *  Created on: May 26, 2016
 *      Author: gwryan
 */

#include "com_palisade_PalisadeCrypto.h"

#include <string>

#include <iostream>
#include <fstream>
#include "../lib/crypto/CryptoContext.h"
#include "../lib/utils/CryptoContextHelper.h"

#include "../lib/utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;

class JavaPalisadeCrypto {
public:
	CryptoContext	*ctx;

	JavaPalisadeCrypto(CryptoContext *ctx) : ctx(ctx) {}
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
(JNIEnv *env, jobject thiz, jstring id)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	CryptoContext *ctx = cp->ctx;

	const char *idS = env->GetStringUTFChars(id, 0);

	LPPublicKeyLTV<ILVector2n> pk(*ctx->getParams());
	LPPrivateKeyLTV<ILVector2n> sk(*ctx->getParams());
	if( !ctx->getAlgorithm()->KeyGen(&pk,&sk) )
		return 0;

	Serialized pubMap, priMap;
	string	pubStr, priStr;

	if ( !pk.Serialize(&pubMap, ctx, idS) || !sk.Serialize(&priMap, ctx, idS) )
		return 0;

	env->ReleaseStringUTFChars(id, idS);

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

static jboolean keySetter(JNIEnv *env, jobject thiz, jbyteArray key, bool (CryptoContext::*f)(const string&))
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return false;

	CryptoContext *ctx = cp->ctx;

	jboolean isCopy;
	char *kData = (char *)env->GetByteArrayElements(key, &isCopy);
	string keyStr(kData, env->GetArrayLength(key));
	if( isCopy ) env->ReleaseByteArrayElements(key, (jbyte *)kData, JNI_ABORT);

	return (ctx->*f)(keyStr);
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPublicKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	return keySetter(env, thiz, key, &CryptoContext::setPublicKey);
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPrivateKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	return keySetter(env, thiz, key, &CryptoContext::setPrivateKey);
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setEvalKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	return keySetter(env, thiz, key, &CryptoContext::setEvalKey);
}


/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    getPalisadeEvalKey
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_generatePalisadeEvalKey
(JNIEnv *env, jobject thiz, jstring id, jbyteArray pub, jbyteArray pri)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	CryptoContext *ctx = cp->ctx;

	const char *idS = env->GetStringUTFChars(id, 0);

	jboolean isCopy, isCopy2;
	char *pData = (char *)env->GetByteArrayElements(pub, &isCopy);
	string pubKstr(pData, env->GetArrayLength(pub));
	char *sData = (char *)env->GetByteArrayElements(pri, &isCopy2);
	string priKstr(sData, env->GetArrayLength(pri));

	if( isCopy ) env->ReleaseByteArrayElements(pub, (jbyte *)pData, JNI_ABORT);
	if( isCopy2 ) env->ReleaseByteArrayElements(pri, (jbyte *)sData, JNI_ABORT);

	// deserialize the keys

	LPPublicKeyLTV<ILVector2n> pk(*ctx->getParams());
	LPPrivateKeyLTV<ILVector2n> sk(*ctx->getParams());

	Serialized pkS, skS;
	if( !SerializableHelper::StringToSerialization(pubKstr, &pkS) ||
			!SerializableHelper::StringToSerialization(priKstr, &skS) ) {
		return 0;
	}

	if( !pk.Deserialize(pkS) || !sk.Deserialize(skS) ) {
		return 0;
	}

	LPEvalKeyLTV<ILVector2n> evalKey(*ctx->getParams());
	if( !ctx->getAlgorithm()->EvalKeyGen(pk, sk, &evalKey) ) {
		return 0;
	}

	Serialized ekS;
	string	ekStr;

	if ( !evalKey.Serialize(&ekS, ctx, idS) ) {
		return 0;
	}

	env->ReleaseStringUTFChars(id, idS);

	if( !SerializableHelper::SerializationToString(ekS, ekStr) ) {
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
(JNIEnv *env, jobject thiz, jstring id, jbyteArray cleartext)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	CryptoContext *ctx = cp->ctx;

	const char *idS = env->GetStringUTFChars(id, 0);

	jboolean isCopy;
	char *clearData = (char *)env->GetByteArrayElements(cleartext, &isCopy);
	long totalBytes = env->GetArrayLength(cleartext);

	LPPublicKeyLTV<ILVector2n> *encryptionKey = ctx->getPublicKey();
	if( encryptionKey == 0 ) return 0;

	// take the cleartext in chunk-size pieces, encrypt and serialize
	const char *bufp = clearData;
	string totalSer = "";

	while( totalBytes > 0 ) {
		usint s = min(totalBytes, ctx->getChunksize());

		ByteArrayPlaintextEncoding ptxt( ByteArray(bufp, s) );
		ptxt.Pad<ZeroPad>(ctx->getPadAmount());

		Ciphertext<ILVector2n> ciphertext;
		ctx->getAlgorithm()->Encrypt(*encryptionKey, ptxt, &ciphertext);

		Serialized txtS;
		string	txtSer;

		if ( !ciphertext.Serialize(&txtS, ctx, idS) )
			break;


		if( !SerializableHelper::SerializationToString(txtS, txtSer) )
			break;

		totalSer += txtSer + "$";

		bufp += s;
		totalBytes -= s;
	}

	jbyteArray evA = 0;

	if( totalBytes == 0 ) { // got it all!
		evA = env->NewByteArray(totalSer.length());
		env->SetByteArrayRegion(evA, 0, totalSer.length(), (jbyte *)totalSer.c_str());
	}

	if( isCopy ) env->ReleaseByteArrayElements(cleartext, (jbyte *)clearData, JNI_ABORT);
	env->ReleaseStringUTFChars(id, idS);


	return evA;
}

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    reEncrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_reEncrypt
(JNIEnv *env, jobject thiz, jstring id, jbyteArray enctext)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	CryptoContext *ctx = cp->ctx;

	const char *idS = env->GetStringUTFChars(id, 0);

	jboolean isCopy;
	char *encData = (char *)env->GetByteArrayElements(enctext, &isCopy);
	usint encBytes = env->GetArrayLength(enctext);
	char *bufp = encData;

	// deserialize the enc test

	LPEvalKeyLTV<ILVector2n> *encryptionKey = ctx->getEvalKey();
	if( encryptionKey == 0 ) return 0;

	Ciphertext<ILVector2n> ciphertext;

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
			return 0;

		if( !ciphertext.Deserialize(kD) )
			return 0;

		Ciphertext<ILVector2n> newCiphertext;

		ctx->getAlgorithm()->ReEncrypt(*encryptionKey, ciphertext, &newCiphertext);

		Serialized txtS;
		string	txtSer;

		if ( !newCiphertext.Serialize(&txtS, ctx, idS) )
			return 0;

		if( !SerializableHelper::SerializationToString(txtS, txtSer) )
			return 0;

		result += txtSer + "$";
	} while( encBytes > 0 );

	jbyteArray evA = 0;
	if( encBytes == 0 ) {
		evA = env->NewByteArray(result.length());
		env->SetByteArrayRegion(evA, 0, result.length(), (jbyte *)result.c_str());
	}

	env->ReleaseStringUTFChars(id, idS);
	if( isCopy ) env->ReleaseByteArrayElements(enctext, (jbyte *)encData, JNI_ABORT);
	return evA;
}

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    decrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_decrypt
(JNIEnv *env, jobject thiz, jstring id, jbyteArray enctext)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	CryptoContext *ctx = cp->ctx;

	const char *idS = env->GetStringUTFChars(id, 0);

	jboolean isCopy;
	char *encData = (char *)env->GetByteArrayElements(enctext, &isCopy);
	usint encBytes = env->GetArrayLength(enctext);
	char *bufp = encData;

	// deserialize the enc text

	LPPrivateKeyLTV<ILVector2n> *decryptionKey = ctx->getPrivateKey();
	if( decryptionKey == 0 ) return 0;

	Ciphertext<ILVector2n> ciphertext;
	ByteArrayPlaintextEncoding plaintext;

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

		if( !ciphertext.Deserialize(kD) )
			break;

		DecodingResult result1 = ctx->getAlgorithm()->Decrypt(*decryptionKey, ciphertext, &plaintext);
		plaintext.Unpad<ZeroPad>();

		const ByteArray& byteArray = plaintext.GetData();
		string ptStr(byteArray.begin(), byteArray.end());
		result += ptStr;
	} while( encBytes > 0 );

	jbyteArray evA = 0;
	if( encBytes == 0 ) {
		evA = env->NewByteArray(result.length());
		env->SetByteArrayRegion(evA, 0, result.length(), (jbyte *)result.c_str());
	}

	env->ReleaseStringUTFChars(id, idS);
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
	CryptoContext *ctx = CryptoContextHelper::getNewContext( cp );
	if( isCopy ) env->ReleaseByteArrayElements(parmJson, (jbyte *)parms, JNI_ABORT);

	if( ctx == 0 ) {
		return 0;
	}

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
