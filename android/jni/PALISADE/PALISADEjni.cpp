/*
 * @file PALISADEjni.cpp - PALISADE jni wrapper
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "com_palisade_PALISADE.h"
#include "palisade.h"
#include "cryptocontext.h"
#include "utils/serial.h"

using namespace lbcrypto;

CryptoContext<Poly> _cc;
vector<Ciphertext<Poly>>	_ctexts;
vector<LPPublicKey<Poly>>	_pubKeys;
vector<LPPrivateKey<Poly>>	_privateKeys;
vector<LPEvalKey<Poly>>		_preKeys;

static bool ByteArrayToString(JNIEnv *env, jbyteArray bytes, string *str) {
	// convert byte array into a std::string
    jsize num_bytes = env->GetArrayLength(bytes);
    jbyte* elements = env->GetByteArrayElements(bytes, NULL);

    if (!elements) {
        return false;
    }

    string sstring((const char *)elements, (size_t)num_bytes);
    *str = sstring;

   // Do not forget to release the element array provided by JNI:
    env->ReleaseByteArrayElements(bytes, elements, JNI_ABORT);

    return true;
}

static jbyteArray StringToByteArray(JNIEnv *env, string sstr) {
    int serlen = sstr.size();

    jbyteArray retval = env->NewByteArray(serlen);
    if (retval == NULL) {
        return NULL; //  out of memory error thrown
    }

    jbyte *bytes = env->GetByteArrayElements(retval, 0);
    for (int i = 0; i < serlen; i++) {
        bytes[i] = sstr[i];
    }

    // move from the temp structure to the java structure
    env->SetByteArrayRegion(retval, 0, serlen, bytes);

    return retval;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadcontext
 * Signature: ([B)Z
 */
JNIEXPORT jboolean JNICALL Java_com_palisade_PALISADE_loadcontext
  (JNIEnv *env, jobject, jbyteArray jser) {

    string sctx;
    if( !ByteArrayToString(env, jser, &sctx) )
    	return false;

    stringstream ss(sctx);
    Serial::Deserialize(_cc, ss);
    return _cc != 0;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadpubkeyctx
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadpubkeyctx
  (JNIEnv *env, jobject, jbyteArray jser) {

    string kctx;
    if( !ByteArrayToString(env, jser, &kctx) )
    	return -1;

    stringstream ss(kctx);

    LPPublicKey<Poly> pubkey;
    Serial::Deserialize(pubkey, ss);

    _pubKeys.push_back(pubkey);
    return _pubKeys.size() - 1;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadprivkeyctx
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadprivkeyctx
(JNIEnv *env, jobject, jbyteArray jser) {

    string kctx;
    if( !ByteArrayToString(env, jser, &kctx) )
    	return -1;

    stringstream ss(kctx);

    LPPrivateKey<Poly> privkey;
    Serial::Deserialize(privkey, ss);

    _privateKeys.push_back(privkey);
    return _pubKeys.size() - 1;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadpubkey
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadpubkey
(JNIEnv *env, jobject unused, jbyteArray jser) {

    return Java_com_palisade_PALISADE_loadpubkeyctx(env, unused, jser);
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    serpubkey
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serpubkey
(JNIEnv *env, jobject, jint pubkeyId) {

	// get the appropriate key
	if( pubkeyId < 0 || pubkeyId >= _pubKeys.size() )
		return NULL;

	auto key = _pubKeys[pubkeyId];

	stringstream ss;
	Serial::Serialize(key,ss);

	return StringToByteArray(env, ss.str());
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadprivkey
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadprivkey
(JNIEnv *env, jobject unused, jbyteArray jser) {

    return Java_com_palisade_PALISADE_loadprivkeyctx(env, unused, jser);
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    serprivkey
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serprivkey
(JNIEnv *env, jobject, jint prikeyId) {

	// get the appropriate key
	if( prikeyId < 0 || prikeyId >= _privateKeys.size() )
		return NULL;

	auto key = _privateKeys[prikeyId];

	stringstream ss;
	Serial::Serialize(key,ss);

	return StringToByteArray(env, ss.str());
}

JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_genprekey
  (JNIEnv *, jobject, jint pubKeyId, jint secretKeyId) {

	if( pubKeyId < 0 || pubKeyId >= _pubKeys.size() )
		return -1;

	auto pubkey = _pubKeys[pubKeyId];

	if( secretKeyId < 0 || secretKeyId >= _privateKeys.size() )
		return -1;

	auto seckey = _privateKeys[secretKeyId];

	auto preKey = _cc->ReKeyGen(pubkey, seckey);

	_preKeys.push_back(preKey);
    return _preKeys.size() - 1;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadprekey
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadprekey
(JNIEnv *env, jobject, jbyteArray jser) {

    string kctx;
    if( !ByteArrayToString(env, jser, &kctx) )
    	return -1;

    stringstream ss(kctx);

    LPEvalKey<Poly> prekey;
    Serial::Deserialize(prekey,ss);

    _preKeys.push_back(prekey);
    return _preKeys.size() - 1;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    serprekey
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serprekey
(JNIEnv *env, jobject, jint kId) {

	// get the appropriate key
	if( kId < 0 || kId >= _preKeys.size() )
		return NULL;

	auto key = _preKeys[kId];

	stringstream ss;
	Serial::Serialize(key,ss);

	return StringToByteArray(env, ss.str());
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    loadct
 * Signature: ([B)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_loadct
(JNIEnv *env, jobject, jbyteArray jser) {

    string kctx;
    if( !ByteArrayToString(env, jser, &kctx) )
    	return -1;

    stringstream ss(kctx);

    Ciphertext<Poly> ct;
    Serial::Deserialize(ct, ss);

    _ctexts.push_back(ct);
    return _ctexts.size() - 1;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    serct
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_serct
(JNIEnv *env, jobject, jint ctId) {

	if( ctId < 0 || ctId >= _ctexts.size() )
		return NULL;

	auto ct = _ctexts[ctId];

	stringstream ss;
	Serial::Serialize(ct,ss);

	return StringToByteArray(env, ss.str());
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    encrypt
 * Signature: ([BI)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_encrypt
  (JNIEnv *env, jobject, jbyteArray ptxt, jint pubkeyId) {

	// get the appropriate key
	if( pubkeyId < 0 || pubkeyId >= _pubKeys.size() )
		return -1;

	auto key = _pubKeys[pubkeyId];

	// convert byte array to string to encrypt
	string sptxt;
	if( !ByteArrayToString(env, ptxt, &sptxt) )
		return -1;

	auto pt = _cc->MakeStringPlaintext(sptxt);

	auto ct = _cc->Encrypt(key, pt);

    _ctexts.push_back(ct);
    return _ctexts.size() - 1;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    reencrypt
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_reencrypt
  (JNIEnv *, jobject, jint ctId, jint keyId) {

	if( ctId < 0 || ctId >= _ctexts.size() )
		return -1;

	auto ct = _ctexts[ctId];

	if( keyId < 0 || keyId >= _preKeys.size() )
		return -1;

	auto key = _preKeys[keyId];

	auto newct = _cc->ReEncrypt(key, ct);

    _ctexts.push_back(newct);
    return _ctexts.size() - 1;
}

/*
 * Class:     com_palisade_PALISADE
 * Method:    decrypt
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_decrypt
  (JNIEnv *env, jobject, jint ctId, jint keyId) {

	if( ctId < 0 || ctId >= _ctexts.size() )
		return NULL;

	auto ct = _ctexts[ctId];

	if( keyId < 0 || keyId >= _privateKeys.size() )
		return NULL;

	auto key = _privateKeys[keyId];

	Plaintext p;
	auto result = _cc->Decrypt(key, ct, &p);

	// FIXME check result

	string ptx = p->GetStringValue();
	return StringToByteArray(env, ptx);
}

JNIEXPORT jstring JNICALL Java_com_palisade_PALISADE_version
	(JNIEnv *env, jobject /* this */) {

    return env->NewStringUTF(GetPALISADEVersion().c_str());
}

#include "cryptocontextparametersets.h"
#include "cryptocontexthelper.h"
#include "cryptocontextgen.h"

JNIEXPORT jbyteArray JNICALL Java_com_palisade_PALISADE_runtest
	(JNIEnv *env, jobject /* this */, jbyteArray pt) {

	string input;
	ByteArrayToString(env, pt, &input);

	CryptoContext<Poly> cc;
	try {
		cc = GenTestCryptoContext<Poly>("StSt", 4096, 256, 80);
	} catch( ... ) {
		return StringToByteArray(env, "no context");
	}

	LPKeyPair<Poly> kp1 = cc->KeyGen();
	LPKeyPair<Poly> kp2 = cc->KeyGen();
	auto preKey = cc->ReKeyGen(kp2.publicKey, kp1.secretKey);

	auto ptx = cc->MakeStringPlaintext(input);
	auto ct1 = cc->Encrypt(kp1.publicKey, ptx);

	auto ct2 = cc->ReEncrypt(preKey, ct1);

	Plaintext result;
	DecryptResult d = cc->Decrypt(kp2.secretKey, ct2, &result);
	return StringToByteArray(env, result->GetStringValue());
}
