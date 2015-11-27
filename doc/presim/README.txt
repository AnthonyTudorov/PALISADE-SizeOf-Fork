Source_presim.cpp was developed for paper "Fast Proxy Re-Encryption for Publish/Subscribe Systems" By Y. Polyakov, K. Rohloff, G. Sahu, and V. Vaikuntananathan.

To run Source_presim

1. Compile Source_presim
2. Copy n_sample.txt, inp_data_1pre.txt, inp_data.txt to the folder where the Source_presim binary is located (needs to be done every time if "make clean" is used)

To change the value of index (based on Root_Of_Unity.xlsx), please 
	update Source_presim.cpp
		PRESimulation(100,0); // Set the second argument to the appropriate index in Root_Of_Unity.xlsx
	update math\cpu8bit\binint.h
		const usint BIT_LENGTH = 70; //set BIT_LENGTH to the value listed in Root_Of_Unity.xlsx
	update math\cpu8bit\dtstruct.h
		const usint FRAGMENTATION_FACTOR = 11; //set FRAGMENTATION_FACTOR to FRAG_FACT in Root_Of_Unity.xlsx
	Recompile Source_presim
	If using "make clean", recopy the input text files