################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/math/cpu8bit/binint8bit.cpp \
../core/lib/math/cpu8bit/binvect8bit.cpp \
../core/lib/math/cpu8bit/dtstruct8bit.cpp \
../core/lib/math/cpu8bit/mempool8bit.cpp 

OBJS += \
./core/lib/math/cpu8bit/binint8bit.o \
./core/lib/math/cpu8bit/binvect8bit.o \
./core/lib/math/cpu8bit/dtstruct8bit.o \
./core/lib/math/cpu8bit/mempool8bit.o 

CPP_DEPS += \
./core/lib/math/cpu8bit/binint8bit.d \
./core/lib/math/cpu8bit/binvect8bit.d \
./core/lib/math/cpu8bit/dtstruct8bit.d \
./core/lib/math/cpu8bit/mempool8bit.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/math/cpu8bit/%.o: ../core/lib/math/cpu8bit/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


