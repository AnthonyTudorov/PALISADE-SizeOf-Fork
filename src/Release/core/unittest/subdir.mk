################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/unittest/Main_TestAll.cpp \
../core/unittest/UnitTestBinInt.cpp \
../core/unittest/UnitTestBinVect.cpp \
../core/unittest/UnitTestDistrGen.cpp \
../core/unittest/UnitTestField2n.cpp \
../core/unittest/UnitTestLatticeElements.cpp \
../core/unittest/UnitTestMatrix.cpp \
../core/unittest/UnitTestMubintvec.cpp \
../core/unittest/UnitTestNTT.cpp \
../core/unittest/UnitTestNative64.cpp \
../core/unittest/UnitTestNbTheory.cpp \
../core/unittest/UnitTestTransform.cpp \
../core/unittest/UnitTestUbint.cpp \
../core/unittest/UnitTestUbintvec.cpp 

OBJS += \
./core/unittest/Main_TestAll.o \
./core/unittest/UnitTestBinInt.o \
./core/unittest/UnitTestBinVect.o \
./core/unittest/UnitTestDistrGen.o \
./core/unittest/UnitTestField2n.o \
./core/unittest/UnitTestLatticeElements.o \
./core/unittest/UnitTestMatrix.o \
./core/unittest/UnitTestMubintvec.o \
./core/unittest/UnitTestNTT.o \
./core/unittest/UnitTestNative64.o \
./core/unittest/UnitTestNbTheory.o \
./core/unittest/UnitTestTransform.o \
./core/unittest/UnitTestUbint.o \
./core/unittest/UnitTestUbintvec.o 

CPP_DEPS += \
./core/unittest/Main_TestAll.d \
./core/unittest/UnitTestBinInt.d \
./core/unittest/UnitTestBinVect.d \
./core/unittest/UnitTestDistrGen.d \
./core/unittest/UnitTestField2n.d \
./core/unittest/UnitTestLatticeElements.d \
./core/unittest/UnitTestMatrix.d \
./core/unittest/UnitTestMubintvec.d \
./core/unittest/UnitTestNTT.d \
./core/unittest/UnitTestNative64.d \
./core/unittest/UnitTestNbTheory.d \
./core/unittest/UnitTestTransform.d \
./core/unittest/UnitTestUbint.d \
./core/unittest/UnitTestUbintvec.d 


# Each subdirectory must supply rules for building sources it contributes
core/unittest/%.o: ../core/unittest/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


