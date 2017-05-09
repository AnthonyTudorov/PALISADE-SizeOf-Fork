################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/math/cpu_int/binint.cpp \
../core/lib/math/cpu_int/binvect.cpp 

OBJS += \
./core/lib/math/cpu_int/binint.o \
./core/lib/math/cpu_int/binvect.o 

CPP_DEPS += \
./core/lib/math/cpu_int/binint.d \
./core/lib/math/cpu_int/binvect.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/math/cpu_int/%.o: ../core/lib/math/cpu_int/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


