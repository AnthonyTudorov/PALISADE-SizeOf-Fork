/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_palisade_PalisadeCrypto */

#ifndef _Included_com_palisade_PalisadeCrypto
#define _Included_com_palisade_PalisadeCrypto
#ifdef __cplusplus
extern "C" {
#endif

//FIXME: Test
JNIEXPORT void JNICALL Java_com_palisade_PalisadeCrypto_writeBytes
  (JNIEnv *, jobject thiz, jbyteArray bytes, jobject outstream);

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    getPalisadeKeyPair
 * Signature: (Ljava/lang/String;)Lcom/palisade/PalisadeKeypair;
 */
JNIEXPORT jobject JNICALL Java_com_palisade_PalisadeCrypto_generatePalisadeKeyPair
  (JNIEnv *, jobject, jstring);

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    getPalisadeEvalKey
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_generatePalisadeEvalKey
  (JNIEnv *, jobject, jstring, jbyteArray, jbyteArray);

JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPublicKey
  (JNIEnv *, jobject thiz, jbyteArray key);
JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setPrivateKey
  (JNIEnv *, jobject thiz, jbyteArray key);
JNIEXPORT jboolean JNICALL Java_com_palisade_PalisadeCrypto_setEvalKey
  (JNIEnv *, jobject thiz, jbyteArray key);

JNIEXPORT jbyteArray Java_com_palisade_PalisadeCrypto_getPalisadeErrorDescription
  (JNIEnv *, jobject thiz);


/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    encrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_encrypt
  (JNIEnv *, jobject, jstring, jbyteArray);

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    reEncrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_reEncrypt
  (JNIEnv *, jobject, jstring, jbyteArray);

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    decrypt
 * Signature: ([B[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PalisadeCrypto_decrypt
  (JNIEnv *, jobject, jstring, jbyteArray);

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    openPalisadeCrypto
 * Signature: ()V
 */
JNIEXPORT jlong JNICALL Java_com_palisade_PalisadeCrypto_openPalisadeCrypto
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_palisade_PalisadeCrypto
 * Method:    closePalisadeCrypto
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_palisade_PalisadeCrypto_closePalisadeCrypto
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif