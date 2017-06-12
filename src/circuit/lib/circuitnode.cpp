#include "circuitnode.h"
#include "circuitgraph.h"

namespace lbcrypto {

int							CircuitNode::step;
vector<CircuitSimulation>	CircuitNode::sim;


CryptoContext<ILDCRT2n> _graph_cc;
shared_ptr<LPPrivateKey<ILDCRT2n>> _graph_key;

ostream& operator<<(ostream& out, const CircuitNode& n)
{
	out << n.nodeId << "  [label=\"" << n.GetId() << "\\n";
	if( n.nodeInputDepth != 0 )
		out << "(d=" + std::to_string(n.nodeInputDepth) + ")\\n";
	out << n.getNodeLabel();

	const Value& val = n.getValue();
	if( _graph_key && val.GetType() != UNKNOWN ) {
		IntPlaintextEncoding pt;
		_graph_cc.Decrypt(_graph_key, {val.GetIntVecValue()}, &pt);
		out << "\\n\\[" << pt << "\\] ";
	}

	out << "\"]; ";

	const vector<usint>& nodeInputs = n.getInputs();
	for( usint input : nodeInputs )
		out << input << " -> " << n.nodeId << "; ";
	if( n.is_output ) {
		out << "{ rank=same; Outputs " << n.nodeId << " }; ";
	}
	if( n.is_input ) {
		out << "{ rank=same; Inputs " << n.nodeId << " }; ";
	}

	return out;
}


// note that for our purposes here, INT and VECTOR_INT can be considered the same thing
// since an INT is simply a vector with one entry and the rest zeroes

Value EvalAddNode::eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg) {
	if( value.GetType() != UNKNOWN )
		return value;

	if( inputs.size() !=2 ) throw std::logic_error("Add requires 2 inputs");

	Value v0( cg.getNodeById(inputs[0])->eval(cc,cg) );
	Value v1( cg.getNodeById(inputs[1])->eval(cc,cg) );
	auto t0 = v0.GetType();
	auto t1 = v1.GetType();

	if( t0 != t1 ) {
		throw std::logic_error("type mismatch for EvalAdd");
	}

	if( t0 == VECTOR_INT ) {
		value = cc.EvalAdd(v0.GetIntVecValue(), v1.GetIntVecValue());
		cout << t1 << endl;
	}
	else {
		throw std::logic_error("eval add for types " + std::to_string(t0) + " and " + std::to_string(t1) + " not implemented");
	}

	Log();
	return value;
}

Value EvalSubNode::eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg) {
	if( value.GetType() != UNKNOWN )
		return value;

	if( inputs.size() !=2 ) throw std::logic_error("Subtract requires 2 inputs");

	Value v0( cg.getNodeById(inputs[0])->eval(cc,cg) );
	Value v1( cg.getNodeById(inputs[1])->eval(cc,cg) );
	auto t0 = v0.GetType();
	auto t1 = v1.GetType();

	if( t0 != t1 ) {
		throw std::logic_error("type mismatch for EvalSub");
	}

	if( t0 == VECTOR_INT ) {
		value = cc.EvalSub(v0.GetIntVecValue(), v1.GetIntVecValue());
	}
	else {
		throw std::logic_error("eval sub for types " + std::to_string(t0) + " and " + std::to_string(t1) + " are not implemented");
	}

	Log();
	return value;
}

Value EvalMultNode::eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg) {
	if( value.GetType() != UNKNOWN )
		return value;

	if( inputs.size() !=2 ) throw std::logic_error("Mult requires 2 inputs");

	Value v0( cg.getNodeById(inputs[0])->eval(cc,cg) );
	Value v1( cg.getNodeById(inputs[1])->eval(cc,cg) );
	auto t0 = v0.GetType();
	auto t1 = v1.GetType();

	if( t0 != t1 ) {
		throw std::logic_error("type mismatch for EvalSub");
	}

	if( t1 == VECTOR_INT ) {
		value = cc.EvalMult(v0.GetIntVecValue(), v1.GetIntVecValue());
	}
	else {
		throw std::logic_error("eval mult for types " + std::to_string(t0) + " and " + std::to_string(t1) + " are not implemented");
	}

	Log();
	return value;
}

Value ModReduceNode::eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg) {
	if( value.GetType() != UNKNOWN )
		return value;

	if( inputs.size() != 1 ) throw std::logic_error("ModReduce must have one input");

	Value v0( cg.getNodeById(inputs[0])->eval(cc,cg) );
	auto t0 = v0.GetType();

	if( t0 == VECTOR_INT ) {
		value = cc.ModReduce(v0.GetIntVecValue());
	}
	else {
		throw std::logic_error("modreduce for type " + std::to_string(t0) + " is not implemented");
	}

	Log();
	return value;
}


}
