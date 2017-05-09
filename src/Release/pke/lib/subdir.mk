################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../pke/lib/bv-vector-impl.cpp \
../pke/lib/bv-vectorarray-impl.cpp \
../pke/lib/bv.cpp \
../pke/lib/ciphertext-vector-impl.cpp \
../pke/lib/ciphertext-vectorarray-impl.cpp \
../pke/lib/cryptocontext-vector-impl.cpp \
../pke/lib/cryptocontext-vectorarray-impl.cpp \
../pke/lib/cryptocontext.cpp \
../pke/lib/cryptocontexthelper.cpp \
../pke/lib/cryptocontextparametersets-impl.cpp \
../pke/lib/fv-vector-impl.cpp \
../pke/lib/fv-vectorarray-impl.cpp \
../pke/lib/fv.cpp \
../pke/lib/ltv-vector-impl.cpp \
../pke/lib/ltv-vectorarray-impl.cpp \
../pke/lib/ltv.cpp \
../pke/lib/matrixser-impl.cpp \
../pke/lib/nullscheme-vector-impl.cpp \
../pke/lib/nullscheme-vectorarray-impl.cpp \
../pke/lib/rationalciphertext.cpp \
../pke/lib/rationalct-vector-impl.cpp \
../pke/lib/rationalct-vectorarray-impl.cpp \
../pke/lib/stst-vector-impl.cpp \
../pke/lib/stst-vectorarray-impl.cpp 

OBJS += \
./pke/lib/bv-vector-impl.o \
./pke/lib/bv-vectorarray-impl.o \
./pke/lib/bv.o \
./pke/lib/ciphertext-vector-impl.o \
./pke/lib/ciphertext-vectorarray-impl.o \
./pke/lib/cryptocontext-vector-impl.o \
./pke/lib/cryptocontext-vectorarray-impl.o \
./pke/lib/cryptocontext.o \
./pke/lib/cryptocontexthelper.o \
./pke/lib/cryptocontextparametersets-impl.o \
./pke/lib/fv-vector-impl.o \
./pke/lib/fv-vectorarray-impl.o \
./pke/lib/fv.o \
./pke/lib/ltv-vector-impl.o \
./pke/lib/ltv-vectorarray-impl.o \
./pke/lib/ltv.o \
./pke/lib/matrixser-impl.o \
./pke/lib/nullscheme-vector-impl.o \
./pke/lib/nullscheme-vectorarray-impl.o \
./pke/lib/rationalciphertext.o \
./pke/lib/rationalct-vector-impl.o \
./pke/lib/rationalct-vectorarray-impl.o \
./pke/lib/stst-vector-impl.o \
./pke/lib/stst-vectorarray-impl.o 

CPP_DEPS += \
./pke/lib/bv-vector-impl.d \
./pke/lib/bv-vectorarray-impl.d \
./pke/lib/bv.d \
./pke/lib/ciphertext-vector-impl.d \
./pke/lib/ciphertext-vectorarray-impl.d \
./pke/lib/cryptocontext-vector-impl.d \
./pke/lib/cryptocontext-vectorarray-impl.d \
./pke/lib/cryptocontext.d \
./pke/lib/cryptocontexthelper.d \
./pke/lib/cryptocontextparametersets-impl.d \
./pke/lib/fv-vector-impl.d \
./pke/lib/fv-vectorarray-impl.d \
./pke/lib/fv.d \
./pke/lib/ltv-vector-impl.d \
./pke/lib/ltv-vectorarray-impl.d \
./pke/lib/ltv.d \
./pke/lib/matrixser-impl.d \
./pke/lib/nullscheme-vector-impl.d \
./pke/lib/nullscheme-vectorarray-impl.d \
./pke/lib/rationalciphertext.d \
./pke/lib/rationalct-vector-impl.d \
./pke/lib/rationalct-vectorarray-impl.d \
./pke/lib/stst-vector-impl.d \
./pke/lib/stst-vectorarray-impl.d 


# Each subdirectory must supply rules for building sources it contributes
pke/lib/%.o: ../pke/lib/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


