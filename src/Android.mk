JNI_PATH := $(call my-dir)

#GMP_WITH_CPLUSPLUS := yes
include $(JNI_PATH)/jni/gmp/Android.mk

##############

include $(JNI_PATH)/jni/ntl/Android.mk

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libPALISADEcore

CORE_FILE_LIST := $(shell find core/lib -name '*.cpp')
LOCAL_SRC_FILES := $(CORE_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := jni/gmp/$(APP_ABI) jni/ntl/prebuilt/$(APP_ABI) ../third-party/rapidjson/include core/lib

LOCAL_CPP_FEATURES := rtti exceptions

LOCAL_SHARED_LIBRARIES += ntl gmp 

include $(BUILD_SHARED_LIBRARY)

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libPALISADEpke

PKE_FILE_LIST := $(shell find pke/lib -name '*-impl.cpp')
LOCAL_SRC_FILES := $(PKE_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := jni/gmp/$(APP_ABI) jni/ntl/prebuilt/$(APP_ABI) ../third-party/rapidjson/include core/lib pke/lib

LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_DISABLE_FATAL_LINKER_WARNINGS=true

LOCAL_SHARED_LIBRARIES += ntl
LOCAL_SHARED_LIBRARIES += gmp PALISADEcore

include $(BUILD_SHARED_LIBRARY)

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libPALISADEjni

JNI_FILE_LIST := $(shell find wrappers/PALISADEjni -name '*.cpp')
LOCAL_SRC_FILES := $(JNI_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := jni/gmp/$(APP_ABI) jni/ntl/prebuilt/$(APP_ABI) ../third-party/rapidjson/include core/lib pke/lib wrappers/PALISADEjni

LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_DISABLE_FATAL_LINKER_WARNINGS=true

LOCAL_SHARED_LIBRARIES += ntl
LOCAL_SHARED_LIBRARIES += gmp PALISADEcore PALISADEpke

include $(BUILD_SHARED_LIBRARY)

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libPALISADEunit

UNIT_FILE_LIST := jni/unittest/testmain.cpp
UNIT_FILE_LIST += $(shell find core/unittest -name '*.cpp')
UNIT_FILE_LIST += $(shell find pke/unittest -name '*.cpp')
LOCAL_SRC_FILES := $(UNIT_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := ../third-party/google-test/googletest ../third-party/google-test/googletest/include jni/gmp/$(APP_ABI) jni/ntl/prebuilt/$(APP_ABI) ../third-party/rapidjson/include core/lib pke/lib 

LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_DISABLE_FATAL_LINKER_WARNINGS=true

LOCAL_LDLIBS := -llog
LOCAL_SHARED_LIBRARIES += ntl
LOCAL_SHARED_LIBRARIES += gmp PALISADEcore PALISADEpke

include $(BUILD_SHARED_LIBRARY)

