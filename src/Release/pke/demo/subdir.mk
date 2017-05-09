################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../pke/demo/BenchMarking.cpp \
../pke/demo/Evaluator.cpp \
../pke/demo/PrettyJson.cpp \
../pke/demo/Source_dcrt.cpp \
../pke/demo/Source_json.cpp \
../pke/demo/Source_presim.cpp \
../pke/demo/demo-crypt-pre-text.cpp \
../pke/demo/demo-she.cpp \
../pke/demo/palisade.cpp 

OBJS += \
./pke/demo/BenchMarking.o \
./pke/demo/Evaluator.o \
./pke/demo/PrettyJson.o \
./pke/demo/Source_dcrt.o \
./pke/demo/Source_json.o \
./pke/demo/Source_presim.o \
./pke/demo/demo-crypt-pre-text.o \
./pke/demo/demo-she.o \
./pke/demo/palisade.o 

CPP_DEPS += \
./pke/demo/BenchMarking.d \
./pke/demo/Evaluator.d \
./pke/demo/PrettyJson.d \
./pke/demo/Source_dcrt.d \
./pke/demo/Source_json.d \
./pke/demo/Source_presim.d \
./pke/demo/demo-crypt-pre-text.d \
./pke/demo/demo-she.d \
./pke/demo/palisade.d 


# Each subdirectory must supply rules for building sources it contributes
pke/demo/%.o: ../pke/demo/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


