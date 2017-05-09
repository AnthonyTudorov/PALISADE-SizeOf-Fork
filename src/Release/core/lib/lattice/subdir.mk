################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../core/lib/lattice/field2n.cpp \
../core/lib/lattice/ildcrtparams.cpp \
../core/lib/lattice/ilparams.cpp \
../core/lib/lattice/ilvector2n.cpp \
../core/lib/lattice/ilvectorarray2n.cpp \
../core/lib/lattice/lattice-impl.cpp 

OBJS += \
./core/lib/lattice/field2n.o \
./core/lib/lattice/ildcrtparams.o \
./core/lib/lattice/ilparams.o \
./core/lib/lattice/ilvector2n.o \
./core/lib/lattice/ilvectorarray2n.o \
./core/lib/lattice/lattice-impl.o 

CPP_DEPS += \
./core/lib/lattice/field2n.d \
./core/lib/lattice/ildcrtparams.d \
./core/lib/lattice/ilparams.d \
./core/lib/lattice/ilvector2n.d \
./core/lib/lattice/ilvectorarray2n.d \
./core/lib/lattice/lattice-impl.d 


# Each subdirectory must supply rules for building sources it contributes
core/lib/lattice/%.o: ../core/lib/lattice/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


