//LAYER 1 : PRIMITIVE DATA STRUCTURES AND OPERATIONS
/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/14/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:	

Description:	
	NBTHEORY is set set of functions that will be used to calculate following:
		- If two numbers are coprime.
		- GCD of two numbers 
		- If number i Prime
		- witnesss function to test if number is prime
		- Roots of unit for provided cyclotomic integer
		- Eulers Totient function phin(n)
		- Generator algorithm

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "nbtheory.h"
#include <math.h>
#include <time.h>
#include <sstream>

//#define DEBUG_NBTHEORY //used to print step by step values in debug mode
//define DEBUG_ROOTS_OF_UNITY


namespace lbcrypto {


/*
	finds roots of unity for given input
	input:	m as number which is cyclotomic(in format of int),
			modulo which is used to find generator (in format of BigBinaryInteger)
	
	output:	root of unity (in format of BigBinaryInteger)
*/
BigBinaryInteger RootOfUnity(int m, const BigBinaryInteger& modulo){
	BigBinaryInteger result;
	return result;

}


/*
	This method can be used to convert int to BigBinaryInteger
*/
BigBinaryInteger intToBigBinaryInteger(usint m){
	/*
	std::ostringstream s;
	s << m;
	BigBinaryInteger result(s.str());
	return result;
	*/
	
	return BigBinaryInteger::intToBigBinaryInteger(m);
	
}

/* Function to reverse bits of num */
unsigned int ReverseBits(unsigned int num, unsigned int msb)
{
    unsigned int reverse_num = 0, i, temp;
 
    for (i = 0; i < msb; i++)
    {
        temp = (num & (1 << i));
        if(temp)
            reverse_num |= (1 << ((msb - 1) - i));
    }
  
    return reverse_num;
}

//gets MSB for an unsigned integer
unsigned int GetMSB32(unsigned int x)
{
    static const unsigned int bval[] =
    {0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4};

    unsigned int r = 0;
    if (x & 0xFFFF0000) { r += 16/1; x >>= 16/1; }
    if (x & 0x0000FF00) { r += 16/2; x >>= 16/2; }
    if (x & 0x000000F0) { r += 16/4; x >>= 16/4; }
    return r + bval[x];
}

/*unsigned int GetMSB32(unsigned int v) {
  static const int pos[32] = {0, 1, 28, 2, 29, 14, 24, 3,
    30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19,
    16, 7, 26, 12, 18, 6, 11, 5, 10, 9};
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  v = (v >> 1) + 1;
  return pos[(v * 0x077CB531UL) >> 27];
}*/

}
