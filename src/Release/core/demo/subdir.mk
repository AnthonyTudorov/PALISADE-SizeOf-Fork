################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/demo/DFTSource.cpp \
../core/demo/MathSource.cpp \
../core/demo/NTTSource.cpp \
../core/demo/NTTSource2.cpp \
../core/demo/ParallelSource.cpp \
../core/demo/SamplingSource.cpp 

OBJS += \
./core/demo/DFTSource.o \
./core/demo/MathSource.o \
./core/demo/NTTSource.o \
./core/demo/NTTSource2.o \
./core/demo/ParallelSource.o \
./core/demo/SamplingSource.o 

CPP_DEPS += \
./core/demo/DFTSource.d \
./core/demo/MathSource.d \
./core/demo/NTTSource.d \
./core/demo/NTTSource2.d \
./core/demo/ParallelSource.d \
./core/demo/SamplingSource.d 


# Each subdirectory must supply rules for building sources it contributes
core/demo/%.o: ../core/demo/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


