JNI_PATH := $(call my-dir)

#GMP_WITH_CPLUSPLUS := yes
include $(JNI_PATH)/jni/gmp/Android.mk

##############

include $(JNI_PATH)/jni/ntl/Android.mk

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libPALISADEcore

CORE_FILE_LIST := $(shell find $(LOCAL_PATH)/../src/core/lib -name '*.cpp')
LOCAL_SRC_FILES := $(CORE_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/jni/gmp/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../src/jni/ntl/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../third-party/cereal/include $(LOCAL_PATH)/../src $(LOCAL_PATH)/../src/core/lib

LOCAL_CPP_FEATURES := rtti exceptions

LOCAL_SHARED_LIBRARIES += ntl gmp 

include $(BUILD_SHARED_LIBRARY)

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libPALISADEpke

PKE_FILE_LIST := $(shell find $(LOCAL_PATH)/../src/pke/lib -name '*-impl.cpp')
LOCAL_SRC_FILES := $(PKE_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/jni/gmp/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../src/jni/ntl/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../third-party/cereal/include $(LOCAL_PATH)/../src $(LOCAL_PATH)/../src/core/lib $(LOCAL_PATH)/../src/pke/lib

LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_DISABLE_FATAL_LINKER_WARNINGS=true

LOCAL_SHARED_LIBRARIES += ntl
LOCAL_SHARED_LIBRARIES += gmp PALISADEcore

include $(BUILD_SHARED_LIBRARY)

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libPALISADEjni

JNI_FILE_LIST := $(shell find $(LOCAL_PATH)/jni/PALISADE -name '*.cpp')
LOCAL_SRC_FILES := $(JNI_FILE_LIST:$(LOCAL_PATH)/%=%)

LOCAL_C_INCLUDES := $(LOCAL_PATH)/jni/gmp/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../src/jni/ntl/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../third-party/cereal/include $(LOCAL_PATH)/../src $(LOCAL_PATH)/../src/core/lib $(LOCAL_PATH)/../src/pke/lib $(LOCAL_PATH)/../src/jni/PALISADE

LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_DISABLE_FATAL_LINKER_WARNINGS=true

LOCAL_SHARED_LIBRARIES += ntl
LOCAL_SHARED_LIBRARIES += gmp PALISADEcore PALISADEpke

include $(BUILD_SHARED_LIBRARY)

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := libgtest

GOOGLETEST_ROOT = $(ANDROID_NDK)/sources/third_party/googletest/googletest

LOCAL_SRC_FILES := $(GOOGLETEST_ROOT)/src/gtest_main.cc $(GOOGLETEST_ROOT)/src/gtest-all.cc

LOCAL_C_INCLUDES := $(GOOGLETEST_ROOT) $(GOOGLETEST_ROOT)/include

LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_DISABLE_FATAL_LINKER_WARNINGS=true

include $(BUILD_SHARED_LIBRARY)

##############

LOCAL_PATH := $(JNI_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := PALISADEunit

UNIT_FILE_LIST := $(LOCAL_PATH)/jni/unittest/testmain2.cpp
UNIT_FILE_LIST += $(shell find $(LOCAL_PATH)/../src/core/unittest -name '*.cpp')
UNIT_FILE_LIST += $(shell find $(LOCAL_PATH)/../src/pke/unittest -name '*.cpp')
LOCAL_SRC_FILES := $(UNIT_FILE_LIST:$(LOCAL_PATH)/%=%)

GOOGLETEST_ROOT = $(ANDROID_NDK)/sources/third_party/googletest/googletest

LOCAL_C_INCLUDES := $(GOOGLETEST_ROOT) $(GOOGLETEST_ROOT)/include $(LOCAL_PATH)/jni/gmp/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../src/jni/ntl/prebuilt/$(APP_ABI) $(LOCAL_PATH)/../third-party/cereal/include $(LOCAL_PATH)/../src $(LOCAL_PATH)/../src/core/lib $(LOCAL_PATH)/../src/pke/lib 

LOCAL_CPP_FEATURES := rtti exceptions
LOCAL_DISABLE_FATAL_LINKER_WARNINGS=true

LOCAL_LDLIBS := -llog
LOCAL_SHARED_LIBRARIES += gtest
LOCAL_SHARED_LIBRARIES += ntl
LOCAL_SHARED_LIBRARIES += gmp PALISADEcore PALISADEpke

include $(BUILD_EXECUTABLE)

