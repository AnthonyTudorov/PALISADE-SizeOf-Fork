Source_presim.cpp was developed for paper "Fast Proxy Re-Encryption for Publish/Subscribe Systems" By Y. Polyakov, K. Rohloff, G. Sahu, and V. Vaikuntananathan.

To run Source_presim

1. Compile Source_presim
2. Copy n_sample.txt, inp_data_1pre.txt, inp_data.txt to the folder from which bin/Source_presim will be executed (current path: pwd)

04/13/2015: THE INSTRUCTIONS LISTED NEXT WERE WRITTEN FOR MATHBACKEND == 1 (set in src/math/backend.h). IT IS RECOMMENDED TO USE MATHBACKEND == 2 - INSTRUCTIONS ARE PROVIDED FURTHER BELOW

To change the value of index (based on Root_Of_Unity.xlsx), please 
	update Source_presim.cpp
		PRESimulation(100,0); // Set the second argument to the appropriate index in Root_Of_Unity.xlsx
	update math\cpu8bit\binint.h
		const usint BIT_LENGTH = 70; //set BIT_LENGTH to the value listed in Root_Of_Unity.xlsx
	update math\cpu8bit\dtstruct.h
		const usint FRAGMENTATION_FACTOR = 11; //set FRAGMENTATION_FACTOR to FRAG_FACT in Root_Of_Unity.xlsx
	Recompile Source_presim
	
IF USING MATHBACKEND == 2, FOLLOW THE FOLLOWING INSTRUCTIONS:

To change the value of index (based on Root_Of_Unity.xlsx), please 
	update Source_presim.cpp
		PRESimulation(100,0); // Set the second argument to the appropriate index in Root_Of_Unity.xlsx
	update math\backend.h
		change "100" in "typedef cpu_int::BigBinaryInteger<uint32_t,100> BigBinaryInteger;" with adequate value. The bit lenghts should be changed in multiples on 32. For example, 97, then 129, next 161, etc.
	Recompile Source_presim