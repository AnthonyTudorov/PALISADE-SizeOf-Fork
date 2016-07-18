//LAYER 4 : PLAINTEXT ENCODING
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

License Information:

Copyright (c) 2015, New Jersey Institute of Technology (NJIT)
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "intencoding.h"
#include <string>

namespace lbcrypto {

	//Impementation of ToInt32
	std::vector<uint32_t> IntArrayPlaintextEncoding::ToInt32() const {
		std::vector<uint32_t> vectorOfInt32(m_data.size());
		for(std::vector<int>::size_type i = 0; i != vectorOfInt32.size(); i++) {
			vectorOfInt32[i] = m_data[i];
		}
		return vectorOfInt32;
	}

	void IntArrayPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVectorArray2n *ilVectorArray2n) const{
		throw std::logic_error("Operation not implemented");
	}

	
	void IntArrayPlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVectorArray2n &ilVectorArray2n){
		throw std::logic_error("Operation not implemented");
	}


	void IntArrayPlaintextEncoding::Encode(const BigBinaryInteger &modulus, ILVector2n *ilVector) const {

		BigBinaryVector temp(ilVector->GetParams().GetCyclotomicOrder()/2,ilVector->GetModulus());

		Format format = COEFFICIENT;

		for (usint i = 0; i<m_data.size(); i++) {
			temp.SetValAtIndex(i, BigBinaryInteger(m_data[i]));
		}

		ilVector->SetValues(temp,format);
	}

	void IntArrayPlaintextEncoding::Decode(const BigBinaryInteger &modulus,  ILVector2n &ilVector) {
		//TODO-Nishanth: Hard-coding rootofUnity for now. Need to find a way to figure out how to set the correct rootOfUnity.
		ilVector.SwitchModulus(modulus, BigBinaryInteger::ONE);
		std::vector<uint32_t> intArray(ilVector.GetValues().GetLength());
		for (usint i = 0; i<ilVector.GetValues().GetLength(); i++) {
			intArray[i] = ilVector.GetValues().GetValAtIndex(i).ConvertToInt();
		}

		this->m_data = intArray;

	}

	
    std::ostream &operator<<(std::ostream &out, const IntArrayPlaintextEncoding &ptxt)
    {
        const std::vector<uint32_t> &intArray = ptxt.GetData();
        out << intArray;
        return out ;
    }
}  // namespace lbcrypto ends
