/**
 * @file stdlatticeparms.cpp: Implementation for the standard values for Lattice Parms, as determined by homomorphicencryption.org
 *
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


#include "stdlatticeparms.h"

namespace lbcrypto {

StdLatticeParm(HEStd_uniform, 1024, 128, 29),
StdLatticeParm(HEStd_uniform, 1024, 192, 21),
StdLatticeParm(HEStd_uniform, 1024, 256, 16),
StdLatticeParm(HEStd_uniform, 2048, 128, 56),
StdLatticeParm(HEStd_uniform, 2048, 192, 39),
StdLatticeParm(HEStd_uniform, 2048, 256, 31),
StdLatticeParm(HEStd_uniform, 4096, 128, 111),
StdLatticeParm(HEStd_uniform, 4096, 192, 77),
StdLatticeParm(HEStd_uniform, 4096, 256, 60),
StdLatticeParm(HEStd_uniform, 8192, 128, 220),
StdLatticeParm(HEStd_uniform, 8192, 192, 154),
StdLatticeParm(HEStd_uniform, 8192, 256, 120),
StdLatticeParm(HEStd_uniform, 16384, 128, 440),
StdLatticeParm(HEStd_uniform, 16384, 192, 307),
StdLatticeParm(HEStd_uniform, 16384, 256, 239),
StdLatticeParm(HEStd_uniform, 32768, 128, 880),
StdLatticeParm(HEStd_uniform, 32768, 192, 612),
StdLatticeParm(HEStd_uniform, 32768, 256, 478),

} /* namespace lbcrypto */
