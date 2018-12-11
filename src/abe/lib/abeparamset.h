/**
 * @file abeparamset.h - Parameter sets for ABE schemes
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
#ifndef ABE_PARAMS_SET_H
#define ABE_PARAMS_SET_H
namespace lbcrypto{
//Map holding minimum ring size in IBE for the given security level
static std::map<SecurityLevel,usint> IBEminringsizemap = {};
//Map holding the IBE parameters for desired security level and ringsize
static std::map<std::pair<SecurityLevel,usint>,usint> IBEparammap = {};

//Map holding minimum ring size and base in CPABE for the given security level and number of attributes
static std::map<std::pair<SecurityLevel,usint>,std::pair<usint,usint>> CPABEminbaseringsizemap = {};
//Map holding the CPABE parameters for desired security level,number of attributes, base and ringsize
static std::map<std::pair<std::pair<std::pair<SecurityLevel,usint>,usint>,usint>,usint> CPABEparammap = {};
}
#endif