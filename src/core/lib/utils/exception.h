/**
 * @file exception.h - framework for exceptions in PALISADE
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


#ifndef SRC_CORE_LIB_UTILS_EXCEPTION_H_
#define SRC_CORE_LIB_UTILS_EXCEPTION_H_

#include <exception>
#include <stdexcept>
#include <string>
#include <iostream>
#include <sstream>

namespace lbcrypto
{

class palisade_error : public std::runtime_error {
	std::string filename;
	int			linenum;

public:
	palisade_error(const char * what) : std::runtime_error(what), filename(""), linenum(0) {}

	const char* what() const throw() {
		std::ostringstream cnvt;

		cnvt << filename << ":" << linenum << " " << runtime_error::what();

		return cnvt.str().c_str();
	}
};

class config_error : public palisade_error {

};

class math_error : public palisade_error {
public:
	math_error(const char * what) : palisade_error(what) {}
};

class not_implemented_error : public palisade_error {

};

class not_available_error : public palisade_error {

};



}

#endif /* SRC_CORE_LIB_UTILS_EXCEPTION_H_ */
