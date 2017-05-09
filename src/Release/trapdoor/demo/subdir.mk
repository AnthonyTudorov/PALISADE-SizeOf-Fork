################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../trapdoor/demo/ABE_EXPERIMENT.cpp \
../trapdoor/demo/ABE_Test.cpp \
../trapdoor/demo/Genes.cpp \
../trapdoor/demo/ObfuscateBitTesterV3.cpp \
../trapdoor/demo/ObfuscateBitTesterV3ACS.cpp \
../trapdoor/demo/ObfuscateParamsGen.cpp \
../trapdoor/demo/ObfuscateSimulator32V3.cpp \
../trapdoor/demo/ObfuscateSimulatorV3.cpp \
../trapdoor/demo/ObfuscateSourceDbcV3.cpp \
../trapdoor/demo/ObfuscateSourceV3.cpp \
../trapdoor/demo/SignatureSource.cpp \
../trapdoor/demo/TestABE.cpp \
../trapdoor/demo/TrapdoorABE.cpp \
../trapdoor/demo/TrapdoorAll.cpp \
../trapdoor/demo/TrapdoorInternal.cpp 

OBJS += \
./trapdoor/demo/ABE_EXPERIMENT.o \
./trapdoor/demo/ABE_Test.o \
./trapdoor/demo/Genes.o \
./trapdoor/demo/ObfuscateBitTesterV3.o \
./trapdoor/demo/ObfuscateBitTesterV3ACS.o \
./trapdoor/demo/ObfuscateParamsGen.o \
./trapdoor/demo/ObfuscateSimulator32V3.o \
./trapdoor/demo/ObfuscateSimulatorV3.o \
./trapdoor/demo/ObfuscateSourceDbcV3.o \
./trapdoor/demo/ObfuscateSourceV3.o \
./trapdoor/demo/SignatureSource.o \
./trapdoor/demo/TestABE.o \
./trapdoor/demo/TrapdoorABE.o \
./trapdoor/demo/TrapdoorAll.o \
./trapdoor/demo/TrapdoorInternal.o 

CPP_DEPS += \
./trapdoor/demo/ABE_EXPERIMENT.d \
./trapdoor/demo/ABE_Test.d \
./trapdoor/demo/Genes.d \
./trapdoor/demo/ObfuscateBitTesterV3.d \
./trapdoor/demo/ObfuscateBitTesterV3ACS.d \
./trapdoor/demo/ObfuscateParamsGen.d \
./trapdoor/demo/ObfuscateSimulator32V3.d \
./trapdoor/demo/ObfuscateSimulatorV3.d \
./trapdoor/demo/ObfuscateSourceDbcV3.d \
./trapdoor/demo/ObfuscateSourceV3.d \
./trapdoor/demo/SignatureSource.d \
./trapdoor/demo/TestABE.d \
./trapdoor/demo/TrapdoorABE.d \
./trapdoor/demo/TrapdoorAll.d \
./trapdoor/demo/TrapdoorInternal.d 


# Each subdirectory must supply rules for building sources it contributes
trapdoor/demo/%.o: ../trapdoor/demo/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


