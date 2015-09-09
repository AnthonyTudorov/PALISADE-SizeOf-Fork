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

All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.

This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
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
