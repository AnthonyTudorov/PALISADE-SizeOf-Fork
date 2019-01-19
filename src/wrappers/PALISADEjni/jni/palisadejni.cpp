#include <jni.h>
#include "include/palisadejni.h"

#include "version.h"
#include "math/backend.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_palisade_PALISADE_version(JNIEnv *env, jobject unused) {
	return env->NewStringUTF(GetPALISADEVersion().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_palisade_PALISADE_test1(JNIEnv *env, jobject unused) {
	return env->NewStringUTF(GetPALISADEVersion().c_str());
}
