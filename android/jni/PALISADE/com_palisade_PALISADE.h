/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_palisade_PALISADE */

#ifndef _Included_com_palisade_PALISADE
#define _Included_com_palisade_PALISADE
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_palisade_PALISADE
 * Method:    loadcontext
 * Signature: ([B)Z
 */
JNIEXPORT jboolean JNICALL Java_com_palisade_PALISADE_loadcontext
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadpubkeyctx
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadpubkeyctx
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadprivkeyctx
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadprivkeyctx
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadpubkey
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadpubkey
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_palisade_PALISADE
 * Method:    serpubkey
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serpubkey
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadprivkey
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadprivkey
  (JNIEnv *, jobject, jbyteArray);

JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_genprekey
  (JNIEnv *, jobject, jint publicKeyId, jint secretKeyId);

/*
 * Class:     com_palisade_PALISADE
 * Method:    serprivkey
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serprivkey
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadprekey
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadprekey
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_palisade_PALISADE
 * Method:    serprekey
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serprekey
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadct
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadct
  (JNIEnv *, jobject, jbyteArray);

/*
 * Class:     com_palisade_PALISADE
 * Method:    serct
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serct
  (JNIEnv *, jobject, jint);

/*
 * Class:     com_palisade_PALISADE
 * Method:    encrypt
 * Signature: ([BI)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_encrypt
  (JNIEnv *, jobject, jbyteArray, jint);

/*
 * Class:     com_palisade_PALISADE
 * Method:    reencrypt
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_reencrypt
  (JNIEnv *, jobject, jint ctid, jint pkid);

/*
 * Class:     com_palisade_PALISADE
 * Method:    decrypt
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_decrypt
  (JNIEnv *, jobject, jint, jint);

JNIEXPORT jstring JNICALL Java_com_palisade_PALISADE_version
  (JNIEnv *, jobject);

JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_runtest
  (JNIEnv *, jobject, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
