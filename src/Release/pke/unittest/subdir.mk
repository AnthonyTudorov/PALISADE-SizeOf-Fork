################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../pke/unittest/Main_TestAll.cpp \
../pke/unittest/UnitTestBV.cpp \
../pke/unittest/UnitTestBVDCRT.cpp \
../pke/unittest/UnitTestBatching.cpp \
../pke/unittest/UnitTestEncryption.cpp \
../pke/unittest/UnitTestFV.cpp \
../pke/unittest/UnitTestLTV.cpp \
../pke/unittest/UnitTestSHE.cpp \
../pke/unittest/UnitTestSHEAdvanced.cpp \
../pke/unittest/UnitTestStatisticalEval.cpp 

OBJS += \
./pke/unittest/Main_TestAll.o \
./pke/unittest/UnitTestBV.o \
./pke/unittest/UnitTestBVDCRT.o \
./pke/unittest/UnitTestBatching.o \
./pke/unittest/UnitTestEncryption.o \
./pke/unittest/UnitTestFV.o \
./pke/unittest/UnitTestLTV.o \
./pke/unittest/UnitTestSHE.o \
./pke/unittest/UnitTestSHEAdvanced.o \
./pke/unittest/UnitTestStatisticalEval.o 

CPP_DEPS += \
./pke/unittest/Main_TestAll.d \
./pke/unittest/UnitTestBV.d \
./pke/unittest/UnitTestBVDCRT.d \
./pke/unittest/UnitTestBatching.d \
./pke/unittest/UnitTestEncryption.d \
./pke/unittest/UnitTestFV.d \
./pke/unittest/UnitTestLTV.d \
./pke/unittest/UnitTestSHE.d \
./pke/unittest/UnitTestSHEAdvanced.d \
./pke/unittest/UnitTestStatisticalEval.d 


# Each subdirectory must supply rules for building sources it contributes
pke/unittest/%.o: ../pke/unittest/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


