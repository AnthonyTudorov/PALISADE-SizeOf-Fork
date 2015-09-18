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

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "dtstruct.h"

namespace lbcrypto{

	CircularQueue::CircularQueue() {
		m_front = m_back = -1;
		CircularQueue::m_size = BUFFER_SIZE/FRAGMENTATION_FACTOR - 1;
		m_count = 0;
 
		for(int i = 0; i <= BUFFER_SIZE/FRAGMENTATION_FACTOR; i++) {
			m_array[i] = 0;
		}
	}
 
	void CircularQueue::Push(uschar* item) {
		if (m_front == 0 && m_back == m_size || m_front == m_back + 1) {
			std::cout << "Queue is full\n";
		}
		else if (m_front == -1 && m_back == -1) {
			m_front = 0;
			m_back = 0;
			m_array[m_front] = item;
			m_count++;
		}
		else if (m_back == m_size) {
			m_back = 0;
			m_array[m_back] = item;
			m_count++;
		}
		else {
			m_back++;
			m_array[m_back] = item;
			m_count++;
		}
	}
 
	void CircularQueue::Pop() {
		if (m_front == -1 && m_back == -1) {
			std::cout << "Queue is empty\n";
		}
		else {
			if (m_front == m_back) {
			m_array[m_front] = 0;
			m_front = -1;
			m_back = -1;
			m_count--;
		}
		else if (m_front == m_size) {
			m_array[m_front] = 0;
			m_front = 0;
			m_count--;
		}
		else {
			m_array[m_front] = 0;
			m_front++;
			m_count--;
		}
		}
	}
 
	void CircularQueue::Show() {
		if (m_count == 0) {
			std::cout << "Queue is empty\n";
		} else {
			for(int i = 0; i < m_size + 1; i++)
				std::cout << m_array[i] << " ";
			std::cout << std::endl;
		}
	}

	int CircularQueue::GetSize() {
		return m_size;
	}

	uschar* CircularQueue::GetFront() {
		return m_array[m_front];
	}

	int CircularQueue::GetBack() {
		return m_back;
	}

}
