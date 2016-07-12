/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 *	Programmers: Dr. Yuriy Polyakov, <polyakov@njit.edu>, Gyana Sahu <grs22@njit.edu>
 * @version 00_03
 *
 * @section LICENSE
 * 
 * Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this 
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this 
 * list of conditions and the following disclaimer in the documentation and/or other 
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS 
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN 
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 *
 *	This code provides basic queueing functionality.
 */

#ifndef LBCRYPTO_MATH_CPU8BIT_MEMPOOL_H
#define LBCRYPTO_MATH_CPU8BIT_MEMPOOL_H

#include <iostream>
#include "../../utils/inttypes.h"
#include "dtstruct8bit.h"

/**
 * @namespace cpu8bit
 * The namespace of cpu8bit
 */
namespace cpu8bit {

	/**
	 * @brief Basic memory pool implementation.
	 */
	class MemoryPoolChar{

	public:

		/**
		 * Basic constructor.	  	  
		 */
		MemoryPoolChar();//ctor

		/**
		 * Allocate memory operation of chunks specified in dtstruct.h file.
		 *
		 * @return the location of the allocated memory
		 */
		uschar* Allocate();

		/**
		 * Allocate memory operation of chunks specified in dtstruct.h file.
		 *
		 * @param memRelease the location of the deallocated memory.
		 */
		void Deallocate(uschar* memRelease);
	
	private:
		CircularQueue m_available;
		uschar m_buffer[BUFFER_SIZE];
	};

}

#endif