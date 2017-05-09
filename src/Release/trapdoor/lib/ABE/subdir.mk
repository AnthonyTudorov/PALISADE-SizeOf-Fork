################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../trapdoor/lib/ABE/Experiments.cpp \
../trapdoor/lib/ABE/KPABE_Test0.cpp \
../trapdoor/lib/ABE/KP_ABE.cpp 

OBJS += \
./trapdoor/lib/ABE/Experiments.o \
./trapdoor/lib/ABE/KPABE_Test0.o \
./trapdoor/lib/ABE/KP_ABE.o 

CPP_DEPS += \
./trapdoor/lib/ABE/Experiments.d \
./trapdoor/lib/ABE/KPABE_Test0.d \
./trapdoor/lib/ABE/KP_ABE.d 


# Each subdirectory must supply rules for building sources it contributes
trapdoor/lib/ABE/%.o: ../trapdoor/lib/ABE/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


