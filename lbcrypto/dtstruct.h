/*
PRE SCHEME PROJECT, Crypto Lab, NJIT
Version: 
	v00.01 
Last Edited: 
	6/1/2015 5:37AM
List of Authors:
	TPOC: 
		Dr. Kurt Rohloff, rohloff@njit.edu
	Programmers:
		Dr. Yuriy Polyakov, polyakov@njit.edu
		Gyana Sahu, grs22@njit.edu
Description:	
	This code provides basic queueing functionality.

All rights retained by NJIT.  Our intention is to release this software as an open-source library under a license comparable in spirit to BSD, Apache or MIT.

This software is being provided as an alpha-test version.  This software has not been audited or externally verified to be correct.  NJIT makes no guarantees or assurances about the correctness of this software.  This software is not ready for use in safety-critical or security-critical applications.
*/

#ifndef LBCRYPTO_DTSTRUCT_H
#define LBCRYPTO_DTSTRUCT_H

#include <iostream>
#include <stdexcept>
#include "inttypes.h"
#include <queue>


namespace lbcrypto {

	const usint FRAGMENTATION_FACTOR = 14;
	
	const usint BUFFER_SIZE = 1024 * 512 * FRAGMENTATION_FACTOR;

	// circular character array implementation of queue used for memory pools
	class CircularQueue {
		private:
			int m_front, m_back, m_size, m_count;
			uschar* m_array[BUFFER_SIZE/FRAGMENTATION_FACTOR];
		public:
			CircularQueue();
			void Push(uschar*);

			void Show();
			void Pop();
			int GetSize();
			//int GetFront();
			int GetBack();
			uschar* GetFront();

	};

}

#endif
