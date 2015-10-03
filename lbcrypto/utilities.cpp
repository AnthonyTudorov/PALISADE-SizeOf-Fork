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
	This file contains utility function functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "utilities.h"

namespace lbcrypto {

//Zero-Padd adds extra zeros to the Input polynomial
//if Input polynomial has a length n less than CycloOrder,
//then it adds CycloOrder-n zeros in the Input Polynomial
BigBinaryVector ZeroPadForward(const BigBinaryVector &InputPoly,usint target_order){

	if(InputPoly.GetLength()<target_order){

		BigBinaryVector ans(target_order);

		for(usint i=0;i<InputPoly.GetLength();i++)
			ans.SetValAtIndex(i,InputPoly.GetValAtIndex(i));

		for(usint i=InputPoly.GetLength();i<target_order;i++)
			ans.SetValAtIndex(i,BigBinaryInteger::ZERO);

		ans.SetModulus(InputPoly.GetModulus());

	    return ans;

	}

	else{
		return BigBinaryVector(InputPoly);
	}
}

//Adds 0 between each BigBinaryInteger to support conversion from Inverse FFT to Inverse CRT
BigBinaryVector ZeroPadInverse(const BigBinaryVector &InputPoly,usint target_order){

	if(InputPoly.GetLength()<target_order){

		BigBinaryVector ans(target_order);

		for(usint i=0;i<InputPoly.GetLength();i++)
		{
			ans.SetValAtIndex(2*i,BigBinaryInteger("0"));
			ans.SetValAtIndex(2*i+1,InputPoly.GetValAtIndex(i));
		}

		ans.SetModulus(InputPoly.GetModulus());

	    return ans;
	}

	else{
		return BigBinaryVector(InputPoly);
	}

}

bool IsPowerOfTwo(usint Input){
	usint tm = 1;
	bool ans = false;
	while(tm<=Input){
		if((tm-Input)==0){
			ans = true;
			break;
		}
		tm <<=1;
	}

	return ans;
}

}//namespace ends here
