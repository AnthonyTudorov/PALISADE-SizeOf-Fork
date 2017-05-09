################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../wrappers/java/PalisadeCryptoWrapper.cpp 

OBJS += \
./wrappers/java/PalisadeCryptoWrapper.o 

CPP_DEPS += \
./wrappers/java/PalisadeCryptoWrapper.d 


# Each subdirectory must supply rules for building sources it contributes
wrappers/java/%.o: ../wrappers/java/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


