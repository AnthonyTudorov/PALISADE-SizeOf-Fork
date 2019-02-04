LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_CPP_FEATURES := exceptions rtti

ANDROID_STD := c++_shared

PBASE := ../../..
THIRDP := ../../../../crossbuild/third-party/include
RJ := ../../../../third-party/rapidjson/include
LOCAL_C_INCLUDES := $(THIRDP) $(RJ) $(PBASE) $(PBASE)/core/lib

LOCAL_MODULE := palisadejni
LOCAL_SRC_FILES := palisadejni.cpp

include $(BUILD_SHARED_LIBRARY)
