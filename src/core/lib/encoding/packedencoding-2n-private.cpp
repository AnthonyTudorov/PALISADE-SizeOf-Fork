/*
* @file packedencoding.cpp Represents and defines plaintext encodings in Palisade with bit packing capabilities.
* @author  TPOC: palisade@njit.edu
*
* @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
*/

#include "packedencoding.h"

namespace lbcrypto {

	void PackedEncoding::SetParams_2n(usint m, const NativeInteger &modulusNI) {

		// Power of two: m/2-point FTT. So we need the mth root of unity
		m_initRoot[modulusNI] = RootOfUnity<NativeInteger>(m, modulusNI);

		// Create the permutations that interchange the automorphism and crt ordering
		// First we create the cyclic group generated by 5 and then adjoin the co-factor by multiplying by 3

		usint phim = (m >> 1);
		usint phim_by_2 = (m >> 2);

		m_toCRTPerm[modulusNI] = std::vector<usint>(phim);
		m_fromCRTPerm[modulusNI] = std::vector<usint>(phim);

		usint curr_index = 1;
		for (usint i = 0; i < phim_by_2; i++) {
			m_toCRTPerm[modulusNI][(curr_index - 1) / 2] = i;
			m_fromCRTPerm[modulusNI][i] = (curr_index - 1) / 2;

			usint cofactor_index = curr_index * 3 % m;
			m_toCRTPerm[modulusNI][(cofactor_index - 1) / 2] = i + phim_by_2;
			m_fromCRTPerm[modulusNI][i + phim_by_2] = (cofactor_index - 1) / 2;

			curr_index = curr_index * 5 % m;

		}

	}

	void PackedEncoding::SetParams_2n(usint m, EncodingParams params) {

		NativeInteger modulusNI(params->GetPlaintextModulus()); //native int modulus
		
		// Power of two: m/2-point FTT. So we need the mth root of unity
		if (params->GetPlaintextRootOfUnity() == 0)
		{
			m_initRoot[modulusNI] = RootOfUnity<NativeInteger>(m, modulusNI);
			params->SetPlaintextRootOfUnity(m_initRoot[modulusNI]);
		}
		else
			m_initRoot[modulusNI] = params->GetPlaintextRootOfUnity();

		// Create the permutations that interchange the automorphism and crt ordering
		// First we create the cyclic group generated by 5 and then adjoin the co-factor by multiplying by 3

		usint phim = (m >> 1);
		usint phim_by_2 = (m >> 2);

		m_toCRTPerm[modulusNI] = std::vector<usint>(phim);
		m_fromCRTPerm[modulusNI] = std::vector<usint>(phim);

		usint curr_index = 1;
		for (usint i = 0; i < phim_by_2; i++) {
			m_toCRTPerm[modulusNI][(curr_index - 1) / 2] = i;
			m_fromCRTPerm[modulusNI][i] = (curr_index - 1) / 2;

			usint cofactor_index = curr_index * 3 % m;
			m_toCRTPerm[modulusNI][(cofactor_index - 1) / 2] = i + phim_by_2;
			m_fromCRTPerm[modulusNI][i + phim_by_2] = (cofactor_index - 1) / 2;

			curr_index = curr_index * 5 % m;

		}

	}

}
