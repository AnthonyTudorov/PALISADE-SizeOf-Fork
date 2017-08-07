/**
 * @file
 * @author  TPOC: Dr. Kurt Rohloff <rohloff@njit.edu>,
 * @programmer Erkay Savas
 * @version 00_05
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
 * This code provides functionality for KP_ABE. The algorithms and naming conventions can be found from
 * this paper: https://eprint.iacr.org/2017/601.pdf
 */

//#include <cmath>
#include <vector>
#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "math/backend.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "../sampling/trapdoor.h"

namespace lbcrypto {

	/*
	 * Input: base
	 * Input: vector of (k+2) elements of $R_q$
	 * Input: $k = \lceil \log_(base){q} \rceil$; i.e. the digit length of the modulus + 1 (in base)
	 * Output: matrix of (k+2)x(k+2) elements of $R_2$ where the coefficients are in balanced representation
	 */
	int PolyVec2BalDecom (const shared_ptr<ILParams> ilParams, int32_t base, int k, const RingMat &pubElemB, RingMat *psi)
	{
		usint ringDimesion = ilParams->GetCyclotomicOrder() >> 1;
		usint m = k+2;
		BigInteger q = ilParams->GetModulus();
		BigInteger big0(0);
		BigInteger bigBase(base);
		for(usint i=0; i<m; i++)
			for(usint j=0; j<m; j++) {
				(*psi)(j, i).SetValuesToZero();
				if ((*psi)(j, i).GetFormat() != COEFFICIENT)
					(*psi)(j, i).SwitchFormat();
			}
		for (usint ii=0; ii<m; ii++) {
			int digit_i;
			Poly tB = pubElemB(0, ii);
			if(tB.GetFormat() != COEFFICIENT)
				tB.SwitchFormat();

			for(usint i=0; i<ringDimesion; i++) {
				BigInteger coeff_i = tB.GetValAtIndex(i);
				int j = 0;
				int flip = 0;
				while(coeff_i != big0) {
//#ifdef OUT
					digit_i = coeff_i.GetDigitAtIndexForBase(1U, (usint)base);
//#endif
					if (digit_i > (base>>1)) {
						digit_i = base-digit_i;
#if MATHBACKEND == 7
						coeff_i = coeff_i+base;    // math backend 7
#else //if MATHBACKEND == 2
						coeff_i = coeff_i+bigBase;    // math backend 2
#endif
						(*psi)(j, ii).SetValAtIndex(i, q-BigInteger(digit_i));
					}
					else if(digit_i == (base>>1)) {
						if (flip == 0) {
#if MATHBACKEND == 7
							coeff_i = coeff_i+base;  // math backend 7
#else //if MATHBACKEND == 2
							coeff_i = coeff_i+bigBase;    // math backend 2
#endif
							(*psi)(j, ii).SetValAtIndex(i, q-BigInteger(digit_i));
						}
						else
							(*psi)(j, ii).SetValAtIndex(i, BigInteger(digit_i));
						flip = flip ^ 1;
					}
					else
						(*psi)(j, ii).SetValAtIndex(i, BigInteger(digit_i));

					coeff_i = coeff_i.DividedBy(bigBase);
					j++;
				}
			}
		}

		psi->SwitchFormat();
		return 0;
	}
}
