/*
 * timingprint.h
 *
 *  Created on: Jun 14, 2017
 *      Author: gwryan
 */

#ifndef TIMINGPRINT_H_
#define TIMINGPRINT_H_

// this is included by cryptocontext.h only

namespace lbcrypto {

// these variables are used to track timings
enum OpType {
	OpKeyGen,
	OpEvalAdd, OpEvalSub, OpEvalMult,
	OpModReduce
};

struct TimingInfo {
	OpType	operation;
	double	timeval;
	TimingInfo(OpType o, double t) : operation(o), timeval(t) {}
};

inline std::ostream& operator<<(std::ostream& out, const OpType& op) {
	switch(op) {
	case OpKeyGen:
		out << "KeyGen";
		break;
	case OpEvalAdd:
		out << "EvalAdd";
		break;
	case OpEvalSub:
		out << "EvalSub";
		break;
	case OpEvalMult:
		out << "EvalMult";
		break;
	case OpModReduce:
		out << "ModReduce";
		break;
	default:
		out << op << "(UNIMPLEMENTED!)";
		break;
	}
	return out;
}

inline std::ostream& operator<<(std::ostream& out, const TimingInfo& t) {
	out << t.operation << ": " << t.timeval;
	return out;
}

}

#endif /* TIMINGPRINT_H_ */
