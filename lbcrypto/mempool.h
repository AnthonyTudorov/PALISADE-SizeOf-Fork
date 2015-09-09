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
	This code provides the core proxy re-encryption functionality.

All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.

This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
*/

#ifndef LBCRYPTO_MEMPOOL_H
#define LBCRYPTO_MEMPOOL_H

#include <iostream>
#include "inttypes.h"
#include "dtstruct.h"

namespace lbcrypto {

	class MemoryPoolChar{

	public:
		MemoryPoolChar();//ctor

		uschar* Allocate();
		void Deallocate(uschar*);
	
	private:
		CircularQueue m_available;
		uschar m_buffer[BUFFER_SIZE];
	};

}

#endif
