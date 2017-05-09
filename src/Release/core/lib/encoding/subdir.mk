################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/encoding/byteplaintextencoding.cpp \
../core/lib/encoding/intplaintextencoding.cpp \
../core/lib/encoding/packedintplaintextencoding.cpp 

OBJS += \
./core/lib/encoding/byteplaintextencoding.o \
./core/lib/encoding/intplaintextencoding.o \
./core/lib/encoding/packedintplaintextencoding.o 

CPP_DEPS += \
./core/lib/encoding/byteplaintextencoding.d \
./core/lib/encoding/intplaintextencoding.d \
./core/lib/encoding/packedintplaintextencoding.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/encoding/%.o: ../core/lib/encoding/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


