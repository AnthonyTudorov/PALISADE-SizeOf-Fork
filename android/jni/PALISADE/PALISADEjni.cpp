/*
 * @file PALISADEjni.cpp - PALISADE jni wrapper
 * @author  TPOC: contact@palisade-crypto.org
 *
 * @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
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
#include "cryptocontexthelper.h"
#include "utils/serialize-binary.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "pubkeylp-ser.h"
#include "bfvrns-ser.h"

using namespace lbcrypto;

vector<Ciphertext<DCRTPoly>>	_ctexts;
vector<LPPublicKey<DCRTPoly>>	_pubKeys;
vector<LPPrivateKey<DCRTPoly>>	_privateKeys;
vector<LPEvalKey<DCRTPoly>>		_preKeys;

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
    CryptoContext<DCRTPoly> cc;
    Serial::Deserialize(cc, ss, SerType::BINARY);
    return CryptoContextFactory<DCRTPoly>::GetContextCount() == 1;
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

    LPPublicKey<DCRTPoly> pubkey;
    Serial::Deserialize(pubkey, ss, SerType::BINARY);

    if( CryptoContextFactory<DCRTPoly>::GetContextCount() != 1 )
	return -1;

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

    LPPrivateKey<DCRTPoly> privkey;
    Serial::Deserialize(privkey, ss, SerType::BINARY);
    if( CryptoContextFactory<DCRTPoly>::GetContextCount() != 1 )
	return -1;

    _privateKeys.push_back(privkey);
    return _privateKeys.size() - 1;
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
	if( pubkeyId < 0 || pubkeyId >= (jint)_pubKeys.size() )
		return NULL;

	auto key = _pubKeys[pubkeyId];

	stringstream ss;
	Serial::Serialize(key,ss, SerType::BINARY);

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
	if( prikeyId < 0 || prikeyId >= (jint)_privateKeys.size() )
		return NULL;

	auto key = _privateKeys[prikeyId];

	stringstream ss;
	Serial::Serialize(key,ss, SerType::BINARY);

	return StringToByteArray(env, ss.str());
}

JNIEXPORT jint JNICALL Java_com_palisade_PALISADE_genprekey
  (JNIEnv *, jobject, jint pubKeyId, jint secretKeyId) {

	if( pubKeyId < 0 || pubKeyId >= (jint)_pubKeys.size() )
		return -1;

	auto pubkey = _pubKeys[pubKeyId];

	if( secretKeyId < 0 || secretKeyId >= (jint)_privateKeys.size() )
		return -1;

	auto seckey = _privateKeys[secretKeyId];

	auto preKey = CryptoContextFactory<DCRTPoly>::GetSingleContext()->ReKeyGen(pubkey, seckey);

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

    LPEvalKey<DCRTPoly> prekey;
    Serial::Deserialize(prekey,ss, SerType::BINARY);

    if( CryptoContextFactory<DCRTPoly>::GetContextCount() != 1 )
	return -1;

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
	if( kId < 0 || kId >= (jint)_preKeys.size() )
		return NULL;

	auto key = _preKeys[kId];

	stringstream ss;
	Serial::Serialize(key,ss, SerType::BINARY);

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

    Ciphertext<DCRTPoly> ct;
    Serial::Deserialize(ct, ss, SerType::BINARY);

    if( CryptoContextFactory<DCRTPoly>::GetContextCount() != 1 )
	return -1;

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

	if( ctId < 0 || ctId >= (jint)_ctexts.size() )
		return NULL;

	auto ct = _ctexts[ctId];

	stringstream ss;
	Serial::Serialize(ct,ss, SerType::BINARY);

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
	if( pubkeyId < 0 || pubkeyId >= (jint)_pubKeys.size() )
		return -1;

	auto key = _pubKeys[pubkeyId];

	// convert byte array to string to encrypt
	string sptxt;
	if( !ByteArrayToString(env, ptxt, &sptxt) )
		return -1;

	vector<int64_t> vec(sptxt.length() + 1);
	vec[0] = sptxt.length();
	for( size_t i = 1; i < sptxt.length() + 1; i++ )
		vec[i] = sptxt[i-1];

	auto pt = CryptoContextFactory<DCRTPoly>::GetSingleContext()->MakeCoefPackedPlaintext(vec);

	auto ct = CryptoContextFactory<DCRTPoly>::GetSingleContext()->Encrypt(key, pt);

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

	if( ctId < 0 || ctId >= (jint)_ctexts.size() )
		return -1;

	auto ct = _ctexts[ctId];

	if( keyId < 0 || keyId >= (jint)_preKeys.size() )
		return -1;

	auto key = _preKeys[keyId];

	auto newct = CryptoContextFactory<DCRTPoly>::GetSingleContext()->ReEncrypt(key, ct);

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

	if( ctId < 0 || ctId >= (jint)_ctexts.size() )
		return NULL;

	auto ct = _ctexts[ctId];

	if( keyId < 0 || keyId >= (jint)_privateKeys.size() )
		return NULL;

	auto key = _privateKeys[keyId];

	Plaintext p;
	/*auto result =*/ CryptoContextFactory<DCRTPoly>::GetSingleContext()->Decrypt(key, ct, &p);
	// FIXME check result

	auto plain = p->GetCoefPackedValue();
	string ptx;

	for( int i = 1; i < plain[0]+1; i++ )
		ptx += (char)(plain[i]&0xff);

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

	CryptoContext<DCRTPoly> cc;
	try {
		cc = GenTestCryptoContext<DCRTPoly>("StSt", 4096, 256, 80);
	} catch( ... ) {
		return StringToByteArray(env, "no context");
	}

	LPKeyPair<DCRTPoly> kp1 = cc->KeyGen();
	LPKeyPair<DCRTPoly> kp2 = cc->KeyGen();
	auto preKey = cc->ReKeyGen(kp2.publicKey, kp1.secretKey);

	auto ptx = cc->MakeStringPlaintext(input);
	auto ct1 = cc->Encrypt(kp1.publicKey, ptx);

	auto ct2 = cc->ReEncrypt(preKey, ct1);

	Plaintext result;
	/*DecryptResult d =*/ cc->Decrypt(kp2.secretKey, ct2, &result);
	// FIXME check result
	return StringToByteArray(env, result->GetStringValue());
}
