/*
 * value.h
 *
 *  Created on: Apr 8, 2017
 *      Author: gerardryan
 */

#ifndef SRC_CIRCUIT_LIB_VALUE_H_
#define SRC_CIRCUIT_LIB_VALUE_H_

#include <iostream>

class Value {
public:
	Value();
	virtual ~Value();

	friend std::ostream& operator<<(std::ostream& out, const Value& v) {
		return out;
	}
};

#endif /* SRC_CIRCUIT_LIB_VALUE_H_ */
