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

All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.

This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
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
