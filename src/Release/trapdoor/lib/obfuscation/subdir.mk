################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../trapdoor/lib/obfuscation/lweconjunctionobfuscatev3.cpp 

OBJS += \
./trapdoor/lib/obfuscation/lweconjunctionobfuscatev3.o 

CPP_DEPS += \
./trapdoor/lib/obfuscation/lweconjunctionobfuscatev3.d 


# Each subdirectory must supply rules for building sources it contributes
trapdoor/lib/obfuscation/%.o: ../trapdoor/lib/obfuscation/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


