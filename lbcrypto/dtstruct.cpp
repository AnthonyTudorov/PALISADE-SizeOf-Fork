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
