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
#include "../../lib/crypto/cryptocontext.h"
#include "../../lib/utils/cryptocontexthelper.h"
#include "../../lib/crypto/cryptocontext.cpp"
#include "../../lib/utils/cryptocontexthelper.cpp"

#include "../../lib/utils/serializablehelper.h"
#include "../../lib/encoding/byteencoding.h"

using namespace std;
using namespace lbcrypto;

class JavaPalisadeCrypto {
public:
	CryptoContext<ILVector2n>	*ctx;
	string						errorMessage;

	JavaPalisadeCrypto(CryptoContext<ILVector2n> *ctx) : ctx(ctx), errorMessage("") {}
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

	CryptoContext<ILVector2n> *ctx = cp->ctx;
	if( ctx == 0 ) return 0;

	const char *idS = env->GetStringUTFChars(id, 0);
	LPPublicKeyLTV<ILVector2n> pk(*ctx->getParams());
	LPPrivateKeyLTV<ILVector2n> sk(*ctx->getParams());
	if( !ctx->getAlgorithm()->KeyGen(&pk,&sk) )
		return 0;
	Serialized pubMap, priMap;
	string	pubStr, priStr;

	if ( !pk.Serialize(&pubMap, idS) || !sk.Serialize(&priMap, idS) )
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

static jboolean keySetter(JNIEnv *env, jobject thiz, jbyteArray key, bool (CryptoContext<ILVector2n>::*f)(const string&))
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return false;

	CryptoContext<ILVector2n> *ctx = cp->ctx;
	if( ctx == 0 ) {
		cp->errorMessage = "No CryptoContext has been set for generateEvalKey";
		return 0;
	}

	jboolean isCopy;
	char *kData = (char *)env->GetByteArrayElements(key, &isCopy);
	string keyStr(kData, env->GetArrayLength(key));
	if( isCopy ) env->ReleaseByteArrayElements(key, (jbyte *)kData, JNI_ABORT);

	return (ctx->*f)(keyStr);
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPublicKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	return keySetter(env, thiz, key, &CryptoContext<ILVector2n>::setPublicKey);
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPrivateKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	return keySetter(env, thiz, key, &CryptoContext<ILVector2n>::setPrivateKey);
}

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setEvalKey
(JNIEnv *env, jobject thiz, jbyteArray key)
{
	return keySetter(env, thiz, key, &CryptoContext<ILVector2n>::setEvalKey);
}

JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_getPalisadeErrorDescription
(JNIEnv *env, jobject thiz)
{
	string errorMessage;

	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	CryptoContext<ILVector2n> *ctx;

	if( cp == 0 ) {
		errorMessage = "No Internal Java Crypto Context is available";
	}
	else {
		ctx = cp->ctx;
		if( ctx == 0 ) {
			errorMessage = "No CryptoContext has been set";
		}
		else
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
(JNIEnv *env, jobject thiz, jstring id, jbyteArray pub, jbyteArray pri)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) {
		return 0;
	}

	CryptoContext<ILVector2n> *ctx = cp->ctx;
	if( ctx == 0 ) {
		cp->errorMessage = "No CryptoContext has been set for generateEvalKey";
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
	if( !SerializableHelper::StringToSerialization(pubKstr, &pkS) ) {
		cp->errorMessage = "Unable to convert public key to JSON document in generateEvalKey";
		return 0;
	}

	if( !SerializableHelper::StringToSerialization(priKstr, &skS) ) {
		cp->errorMessage = "Unable to convert private key to JSON document in generateEvalKey";
		return 0;
	}

	if( !pk.Deserialize(pkS, ctx) ) {
		cp->errorMessage = "Unable to deserialize public key in generateEvalKey";
		return 0;
	}
	if( !sk.Deserialize(skS, ctx) ) {
		cp->errorMessage = "Unable to deserialize private key in generateEvalKey";
		return 0;
	}

	LPEvalKeyLTV<ILVector2n> evalKey(*ctx->getParams());
	if( !ctx->getAlgorithm()->EvalKeyGen(pk, sk, &evalKey) ) {
		cp->errorMessage = "EvalKeyGen failed in generateEvalKey";
		return 0;
	}

	Serialized ekS;
	string	ekStr;

	if ( !evalKey.Serialize(&ekS, idS) ) {
		cp->errorMessage = "Unable to serialize eval key in generateEvalKey";
		return 0;
	}

	env->ReleaseStringUTFChars(id, idS);

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
(JNIEnv *env, jobject thiz, jstring id, jbyteArray cleartext)
{
	JavaPalisadeCrypto* cp = getCrypto(env, thiz);
	if( cp == 0 ) return 0;

	CryptoContext<ILVector2n> *ctx = cp->ctx;
	if( ctx == 0 ) {
		cp->errorMessage = "No CryptoContext has been set for encrypt";
		return 0;
	}

	if( cleartext == 0 ) {
		cp->errorMessage = "No cleartext was provided to encrypt";
		return 0;
	}

	const char *idS = env->GetStringUTFChars(id, 0);

	jboolean isCopy;
	char *clearData = (char *)env->GetByteArrayElements(cleartext, &isCopy);
	long totalBytes = env->GetArrayLength(cleartext);

	LPPublicKeyLTV<ILVector2n> *encryptionKey = ctx->getPublicKey();
	if( encryptionKey == 0 ) {
		cp->errorMessage = "No public key has been set for encrypt";
		return 0;
	}

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

		if ( !ciphertext.Serialize(&txtS, idS) )
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

	CryptoContext<ILVector2n> *ctx = cp->ctx;
	if( ctx == 0 ) return 0;

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

		if( !ciphertext.Deserialize(kD, ctx) )
			return 0;

		Ciphertext<ILVector2n> newCiphertext;

		ctx->getAlgorithm()->ReEncrypt(*encryptionKey, ciphertext, &newCiphertext);

		Serialized txtS;
		string	txtSer;

		if ( !newCiphertext.Serialize(&txtS, idS) )
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

	CryptoContext<ILVector2n> *ctx = cp->ctx;
	if( ctx == 0 ) return 0;

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

		if( !ciphertext.Deserialize(kD, ctx) )
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
	CryptoContext<ILVector2n> *ctx = CryptoContextHelper<ILVector2n>::getNewContext( cp );
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
