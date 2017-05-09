################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/math/exp_int/mubintvec.cpp \
../core/lib/math/exp_int/ubint.cpp \
../core/lib/math/exp_int/ubintvec.cpp 

OBJS += \
./core/lib/math/exp_int/mubintvec.o \
./core/lib/math/exp_int/ubint.o \
./core/lib/math/exp_int/ubintvec.o 

CPP_DEPS += \
./core/lib/math/exp_int/mubintvec.d \
./core/lib/math/exp_int/ubint.d \
./core/lib/math/exp_int/ubintvec.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/math/exp_int/%.o: ../core/lib/math/exp_int/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


