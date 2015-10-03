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
	This code provides the core memory pool functionality.

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "mempool.h"

namespace lbcrypto{

	MemoryPoolChar::MemoryPoolChar(){
		//initiate the available queue
		for(usint i=0;i<lbcrypto::BUFFER_SIZE;i+=FRAGMENTATION_FACTOR){
			//std::cout<<(int)(buffer+i)<<std::endl;
			/*for(usint j=0;j<fragmentationFactor;j++)
				*(buffer+i+j)=0;*/
			m_available.Push((m_buffer+i));
		}

		//std::cout<<"Memory Pool started with size"<<m_available.GetSize()<<std::endl;

	}

	uschar * MemoryPoolChar::Allocate(){
		if(m_available.GetSize()==0)
			throw std::bad_alloc();
		else{
			uschar* temp = m_available.GetFront();
			//std::cout<<(int)temp<<std::endl;
			m_available.Pop();
			return temp;
		}
	}

	void MemoryPoolChar::Deallocate(uschar* memRelease){
		//std::cout<<(int)memRelease<<std::endl;
		if(memRelease!=NULL)
			m_available.Push(memRelease);
		memRelease = NULL;
	}

}
