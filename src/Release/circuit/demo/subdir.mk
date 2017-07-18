################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../circuit/demo/gentimingest.cpp \
../circuit/demo/inner-product-demos.cpp \
../circuit/demo/palcircuit.cpp 

OBJS += \
./circuit/demo/gentimingest.o \
./circuit/demo/inner-product-demos.o \
./circuit/demo/palcircuit.o 

CPP_DEPS += \
./circuit/demo/gentimingest.d \
./circuit/demo/inner-product-demos.d \
./circuit/demo/palcircuit.d 


# Each subdirectory must supply rules for building sources it contributes
circuit/demo/%.o: ../circuit/demo/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


