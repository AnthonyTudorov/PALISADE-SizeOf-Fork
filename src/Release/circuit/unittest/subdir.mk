################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../circuit/unittest/Main_TestAll.cpp 

OBJS += \
./circuit/unittest/Main_TestAll.o 

CPP_DEPS += \
./circuit/unittest/Main_TestAll.d 


# Each subdirectory must supply rules for building sources it contributes
circuit/unittest/%.o: ../circuit/unittest/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


