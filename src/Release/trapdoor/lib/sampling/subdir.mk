################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../trapdoor/lib/sampling/dgsampling.cpp \
../trapdoor/lib/sampling/trapdoor.cpp 

OBJS += \
./trapdoor/lib/sampling/dgsampling.o \
./trapdoor/lib/sampling/trapdoor.o 

CPP_DEPS += \
./trapdoor/lib/sampling/dgsampling.d \
./trapdoor/lib/sampling/trapdoor.d 


# Each subdirectory must supply rules for building sources it contributes
trapdoor/lib/sampling/%.o: ../trapdoor/lib/sampling/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


