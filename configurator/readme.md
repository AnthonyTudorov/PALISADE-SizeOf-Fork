## Characterize the problem

1. Represent the application as a cryptographic circuit
2. Use the PALISADE circuit analysis tool to determine the characteristics of the circuit
3. Result, from circuit tool, is APP-PROFILE

## Characterize the machine

1. Use open source tool to determine details about clock speed, memory, etc
2. Result is ENV-PROFILE

## Determine how to run the app

1. APP-PROFILE + ENV-PROFILE into the configurator
2. Result is DEPLOY-PROFILE

## Configurator:

- NOW only uses BFVrns, but could use any
- NOW does not take ENV-PROFILE into account at all; will need this for parallels and cores
- generates 5 different possible configuration parameter sets, just varying the security level
between 1.001 and 1.005

APPLICATION runs and is given the DEPLOY-PROFILE to run

I have measurements on Mac, Win, Lin


Experimental results:

Run the 8-neighbor Laplacian image sharpening algorithm on a 64x64 encrypted image


