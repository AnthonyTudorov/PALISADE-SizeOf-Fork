################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/utils/debug.cpp \
../core/lib/utils/hashutil.cpp \
../core/lib/utils/palisadebase64.cpp \
../core/lib/utils/serializablehelper.cpp \
../core/lib/utils/utilities.cpp 

OBJS += \
./core/lib/utils/debug.o \
./core/lib/utils/hashutil.o \
./core/lib/utils/palisadebase64.o \
./core/lib/utils/serializablehelper.o \
./core/lib/utils/utilities.o 

CPP_DEPS += \
./core/lib/utils/debug.d \
./core/lib/utils/hashutil.d \
./core/lib/utils/palisadebase64.d \
./core/lib/utils/serializablehelper.d \
./core/lib/utils/utilities.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/utils/%.o: ../core/lib/utils/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


