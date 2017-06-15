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
	OpMultiPartyKeyGenKey, OpMultiPartyKeyGenKeyvec,
	OpMultiPartyDecryptLead, OpMultiPartyDecryptMain, OpMultiPartyDecryptFusion,
	OpSparseKeyGen,
	OpReKeyGenPubPri, OpReKeyGenPriPri,
	OpEvalSumKeyGen, OpEvalMultKeyGen,
	OpKeySwitchGen,
	OpEncrypt, OpEncryptMatrixPlain, OpEncryptMatrixPacked,
	OpDecrypt, OpDecryptMatrixPlain, OpDecryptMatrixPacked,
	OpReEncrypt,
	OpEvalAdd, OpEvalAddPlain, OpEvalSub, OpEvalSubPlain,
	OpEvalMult, OpEvalMultKey, OpEvalMultPlain, OpEvalNeg,
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
	case OpMultiPartyKeyGenKey:
		out << "MultipartyKeyGen(key)";
		break;
	case OpMultiPartyKeyGenKeyvec:
		out << "MultipartyKeyGen(vector<key>)";
		break;
	case OpMultiPartyDecryptLead:
		out << "MultiPartyDecryptLead";
		break;
	case OpMultiPartyDecryptMain:
		out << "MultiPartyDecryptMain";
		break;
	case OpMultiPartyDecryptFusion:
		out << "MultiPartyDecryptFusion";
		break;
	case OpSparseKeyGen:
		out << "SparseKeyGen";
		break;
	case OpReKeyGenPubPri:
		out << "ReKeyGen(pubkey,privkey)";
		break;
	case OpReKeyGenPriPri:
		out << "ReKeyGen(privkey,privkey)";
		break;
	case OpEvalSumKeyGen:
		out << "EvalSumKeyGen";
		break;
	case OpEvalMultKeyGen:
		out << "EvalMultKeyGen";
		break;
	case OpEncrypt:
		out << "Encrypt";
		break;
	case OpEncryptMatrixPlain:
		out << "EncryptMatrix(intplaintext)";
		break;
	case OpEncryptMatrixPacked:
		out << "EncryptMatrix(packedintplaintext)";
		break;
	case OpDecrypt:
		out << "Decrypt";
		break;
	case OpDecryptMatrixPlain:
		out << "DecryptMatrix(intplaintext)";
		break;
	case OpDecryptMatrixPacked:
		out << "DecryptMatrix(packedintplaintext)";
		break;
	case OpReEncrypt:
		out << "ReEncrypt";
		break;

	case OpEvalAdd:
		out << "EvalAdd";
		break;
	case OpEvalAddPlain:
		out << "EvalAddPlain";
		break;
	case OpEvalNeg:
		out << "EvalNeg";
		break;
	case OpEvalSub:
		out << "EvalSub";
		break;
	case OpEvalSubPlain:
		out << "EvalSubPlain";
		break;
	case OpEvalMult:
		out << "EvalMult";
		break;
	case OpEvalMultKey:
		out << "EvalMult(key)";
		break;
	case OpEvalMultPlain:
		out << "EvalMultPlain";
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
