################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../wrappers/python/conjinterface.cpp \
../wrappers/python/pycrypto.cpp 

OBJS += \
./wrappers/python/conjinterface.o \
./wrappers/python/pycrypto.o 

CPP_DEPS += \
./wrappers/python/conjinterface.d \
./wrappers/python/pycrypto.d 


# Each subdirectory must supply rules for building sources it contributes
wrappers/python/%.o: ../wrappers/python/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


