################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/math/gmp_int/gmpint.cpp \
../core/lib/math/gmp_int/gmpintvec.cpp \
../core/lib/math/gmp_int/mgmpint.cpp \
../core/lib/math/gmp_int/mgmpintvec.cpp 

OBJS += \
./core/lib/math/gmp_int/gmpint.o \
./core/lib/math/gmp_int/gmpintvec.o \
./core/lib/math/gmp_int/mgmpint.o \
./core/lib/math/gmp_int/mgmpintvec.o 

CPP_DEPS += \
./core/lib/math/gmp_int/gmpint.d \
./core/lib/math/gmp_int/gmpintvec.d \
./core/lib/math/gmp_int/mgmpint.d \
./core/lib/math/gmp_int/mgmpintvec.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/math/gmp_int/%.o: ../core/lib/math/gmp_int/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


