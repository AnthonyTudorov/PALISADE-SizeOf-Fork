################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../trapdoor/unittest/Main_TestAll.cpp \
../trapdoor/unittest/UnitTestSignatureGPV.cpp \
../trapdoor/unittest/UnitTestTrapdoor.cpp 

OBJS += \
./trapdoor/unittest/Main_TestAll.o \
./trapdoor/unittest/UnitTestSignatureGPV.o \
./trapdoor/unittest/UnitTestTrapdoor.o 

CPP_DEPS += \
./trapdoor/unittest/Main_TestAll.d \
./trapdoor/unittest/UnitTestSignatureGPV.d \
./trapdoor/unittest/UnitTestTrapdoor.d 


# Each subdirectory must supply rules for building sources it contributes
trapdoor/unittest/%.o: ../trapdoor/unittest/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


