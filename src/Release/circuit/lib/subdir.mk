################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../circuit/lib/circuitgraph.cpp \
../circuit/lib/circuitinput.cpp \
../circuit/lib/circuitnode.cpp \
../circuit/lib/parse.cpp \
../circuit/lib/parsedriver.cpp \
../circuit/lib/scan.cpp 

OBJS += \
./circuit/lib/circuitgraph.o \
./circuit/lib/circuitinput.o \
./circuit/lib/circuitnode.o \
./circuit/lib/parse.o \
./circuit/lib/parsedriver.o \
./circuit/lib/scan.o 

CPP_DEPS += \
./circuit/lib/circuitgraph.d \
./circuit/lib/circuitinput.d \
./circuit/lib/circuitnode.d \
./circuit/lib/parse.d \
./circuit/lib/parsedriver.d \
./circuit/lib/scan.d 


# Each subdirectory must supply rules for building sources it contributes
circuit/lib/%.o: ../circuit/lib/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


