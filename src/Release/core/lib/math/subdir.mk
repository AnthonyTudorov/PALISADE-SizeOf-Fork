################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/math/binaryuniformgenerator.cpp \
../core/lib/math/discretegaussiangenerator.cpp \
../core/lib/math/discreteuniformgenerator.cpp \
../core/lib/math/distributiongenerator.cpp \
../core/lib/math/matrix.cpp \
../core/lib/math/matrixser.cpp \
../core/lib/math/matrixstrassen.cpp \
../core/lib/math/nbtheory.cpp \
../core/lib/math/ternaryuniformgenerator.cpp \
../core/lib/math/transfrm.cpp 

OBJS += \
./core/lib/math/binaryuniformgenerator.o \
./core/lib/math/discretegaussiangenerator.o \
./core/lib/math/discreteuniformgenerator.o \
./core/lib/math/distributiongenerator.o \
./core/lib/math/matrix.o \
./core/lib/math/matrixser.o \
./core/lib/math/matrixstrassen.o \
./core/lib/math/nbtheory.o \
./core/lib/math/ternaryuniformgenerator.o \
./core/lib/math/transfrm.o 

CPP_DEPS += \
./core/lib/math/binaryuniformgenerator.d \
./core/lib/math/discretegaussiangenerator.d \
./core/lib/math/discreteuniformgenerator.d \
./core/lib/math/distributiongenerator.d \
./core/lib/math/matrix.d \
./core/lib/math/matrixser.d \
./core/lib/math/matrixstrassen.d \
./core/lib/math/nbtheory.d \
./core/lib/math/ternaryuniformgenerator.d \
./core/lib/math/transfrm.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/math/%.o: ../core/lib/math/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


