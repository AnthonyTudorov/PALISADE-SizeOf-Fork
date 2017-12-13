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

		ModulusM modulusM(modulusNI,m);

		// Power of two: m/2-point FTT. So we need the mth root of unity
		m_initRoot[modulusM] = RootOfUnity<NativeInteger>(m, modulusNI);

	}

	void PackedEncoding::SetParams_2n(usint m, EncodingParams params) {

		NativeInteger modulusNI(params->GetPlaintextModulus()); //native int modulus

		ModulusM modulusM(modulusNI,m);

		// Power of two: m/2-point FTT. So we need the mth root of unity
		if (params->GetPlaintextRootOfUnity() == 0)
		{
			m_initRoot[modulusM] = RootOfUnity<NativeInteger>(m, modulusNI);
			params->SetPlaintextRootOfUnity(m_initRoot[modulusM].ConvertToInt());
		}
		else
			m_initRoot[modulusM] = params->GetPlaintextRootOfUnity();

	}

}
