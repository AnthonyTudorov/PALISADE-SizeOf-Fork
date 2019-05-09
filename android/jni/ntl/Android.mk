LOCAL_PATH := $(call my-dir)

############################
# Definition for libntl    #
############################
include $(CLEAR_VARS)
LOCAL_MODULE := ntl
LOCAL_SRC_FILES := prebuilt/$(TARGET_ARCH_ABI)/libntl.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/prebuilt/$(TARGET_ARCH_ABI)
include $(PREBUILT_SHARED_LIBRARY)
