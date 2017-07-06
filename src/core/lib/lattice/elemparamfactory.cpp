/**
 * @file plaintext.h Represents and defines plaintext objects in Palisade.
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

#include "elemparamfactory.h"

namespace lbcrypto {

struct ElemParamFactory::ElemParmSet ElemParamFactory::DefaultSet[] = {
		{ 16, 8,
				BigInteger("34359738641"),
				BigInteger("5688225070")
		},
		{ 1024, 512,
				BigInteger("525313"),
				BigInteger("513496")
		},
		{ 2048, 1024,
				BigInteger("34359724033"), // (1<<35) - (1<<14) + (1<<11) + 1
				BigInteger("11574709249")
		},
		{ 4096, 2048,
				BigInteger("1152921504606830593"), // (1<<60) - (1<<14) + 1
				BigInteger("512911795914445712")
		},
		{ 8192, 4096,
				BigInteger("83076749736557242056487941267259393"), // (1<<116) - (1<<18) + 1
				BigInteger("7174246090155309681020695614225666")
		},
		{ 16384, 8192,
				BigInteger("107839786668602559178668060348078522694548577690162289924414373888001"), // (1<<226) - (1<<26) + 1
				BigInteger("19714040362369820282800943210624474894547843835164146989800867233414")
		},
		{ 32768, 16384, // (1<<435) - (1<<33) + 1
				BigInteger("88725430211866075506509253892578678509965986412026130405455346579667881849780019937279180995332466499116518750764914298518583115777"),
				BigInteger("24606764922249713678970948359954996996097393444674350201334048272857296990709662751965279696328118503540981820164645549732655298796")
		},
};

} /* namespace lbcrypto */
