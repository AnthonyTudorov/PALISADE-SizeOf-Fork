################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include wrappers/python/subdir.mk
-include wrappers/java/subdir.mk
-include trapdoor/unittest/subdir.mk
-include trapdoor/lib/signature/subdir.mk
-include trapdoor/lib/sampling/subdir.mk
-include trapdoor/lib/obfuscation/subdir.mk
-include trapdoor/lib/ABE/subdir.mk
-include trapdoor/demo/subdir.mk
-include trapdoor/bin/unittest/subdir.mk
-include trapdoor/bin/lib/signature/subdir.mk
-include trapdoor/bin/lib/sampling/subdir.mk
-include trapdoor/bin/lib/obfuscation/subdir.mk
-include trapdoor/bin/lib/ABE/subdir.mk
-include trapdoor/bin/demo/subdir.mk
-include pke/unittest/subdir.mk
-include pke/lib/subdir.mk
-include pke/demo/subdir.mk
-include pke/bin/unittest/subdir.mk
-include pke/bin/lib/subdir.mk
-include pke/bin/demo/subdir.mk
-include core/unittest/subdir.mk
-include core/lib/utils/subdir.mk
-include core/lib/math/native64/subdir.mk
-include core/lib/math/exp_int/subdir.mk
-include core/lib/math/cpu_int/subdir.mk
-include core/lib/math/subdir.mk
-include core/lib/lattice/subdir.mk
-include core/lib/encoding/subdir.mk
-include core/demo/subdir.mk
-include core/bin/unittest/subdir.mk
-include core/bin/lib/utils/subdir.mk
-include core/bin/lib/math/subdir.mk
-include core/bin/lib/lattice/subdir.mk
-include core/bin/lib/encoding/subdir.mk
-include core/bin/demo/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(CC_DEPS)),)
-include $(CC_DEPS)
endif
ifneq ($(strip $(C++_DEPS)),)
-include $(C++_DEPS)
endif
ifneq ($(strip $(C_UPPER_DEPS)),)
-include $(C_UPPER_DEPS)
endif
ifneq ($(strip $(CXX_DEPS)),)
-include $(CXX_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(CPP_DEPS)),)
-include $(CPP_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: palisade-eclipse

# Tool invocations
palisade-eclipse: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Cross G++ Linker'
	g++  -o "palisade-eclipse" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(CC_DEPS)$(C++_DEPS)$(EXECUTABLES)$(OBJS)$(C_UPPER_DEPS)$(CXX_DEPS)$(C_DEPS)$(CPP_DEPS) palisade-eclipse
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
