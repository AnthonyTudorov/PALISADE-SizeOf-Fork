################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/math/native64/binint.cpp 

OBJS += \
./core/lib/math/native64/binint.o 

CPP_DEPS += \
./core/lib/math/native64/binint.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/math/native64/%.o: ../core/lib/math/native64/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


