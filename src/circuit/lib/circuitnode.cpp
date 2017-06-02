#include "circuitnode.h"
#include "circuitgraph.h"
#include <typeinfo>

namespace lbcrypto {

ostream& operator<<(ostream& out, const CircuitNode& n)
{
	out << n.nodeId << "  [label=\"";
	if( n.nodeInputDepth != 0 )
		out << "(" + std::to_string(n.nodeInputDepth) + ")\\n";
	out << n.getNodeLabel() << "\"";
//	const Value& val = n.getValue();
//	if( val != NULL )
//		out << "\\n\\[" << n.getValue()->GetElement() << "\\] \" ";

	//out << " xlabel=\"" << n.GetId() << "\"";
	out << "]; ";

	const vector<int>& nodeInputs = n.getInputs();
	for( int input : nodeInputs )
		out << input << " -> " << n.nodeId << "; ";
	if( n.is_output ) {
		out << "{ rank=same; Outputs " << n.nodeId << " }; ";
	}
	else if( typeid(n) == typeid(Input) ) {
		out << "{ rank=same; Inputs " << n.nodeId << " }; ";
	}

	return out;
}


// note that for our purposes here, INT and VECTOR_INT can be considered the same thing
// since an INT is simply a vector with one entry and the rest zeroes

Value EvalAddNode::eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
	// gather together all of the inputs to this gate and add them
	if( inputs.size() == 0 ) throw std::logic_error("Cannot add, no inputs");

	auto t1 = cg.getNodeById(inputs[0])->GetType();
	Value sum( cg.getNodeById(inputs[0])->getValue() );

	if( t1 == INT ) t1 = VECTOR_INT;

	for( size_t i = 1; i < inputs.size(); i++ ) {
		auto t2 = cg.getNodeById(inputs[i])->GetType();
		if( t2 == INT ) t2 = VECTOR_INT;

		if( t1 != t2 ) {
			throw std::logic_error("type mismatch for EvalAdd");
		}
		else if( t1 == VECTOR_INT ) {
			sum = cc.EvalAdd(sum.GetIntVecValue(), cg.getNodeById( inputs[i] )->getValue().GetIntVecValue());
			t1 = sum.GetType(); // will be a vec or a matrix
		}
		else {
			throw std::logic_error("not implemented");
		}
	}

	return value = sum;
}

Value EvalSubNode::eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
	// gather together all of the inputs to this gate and subtract them
	if( inputs.size() == 0 ) throw std::logic_error("Cannot subtract, no inputs");

	auto t1 = cg.getNodeById(inputs[0])->GetType();
	Value sum( cg.getNodeById(inputs[0])->getValue() );

	if( t1 == INT ) t1 = VECTOR_INT;

	for( size_t i = 1; i < inputs.size(); i++ ) {
		auto t2 = cg.getNodeById(inputs[i])->GetType();
		if( t2 == INT ) t2 = VECTOR_INT;

		if( t1 != t2 ) {
			throw std::logic_error("type mismatch for EvalSub");
		}
		else if( t1 == VECTOR_INT ) {
			sum = cc.EvalSub(sum.GetIntVecValue(), cg.getNodeById( inputs[i] )->getValue().GetIntVecValue());
			t1 = sum.GetType();
		}
		else {
			throw std::logic_error("not implemented");
		}
	}

	return value = sum;
}

Value EvalMultNode::eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
	// gather together all of the inputs to this gate and multiply them
	if( inputs.size() == 0 ) throw std::logic_error("Cannot multiply, no inputs");

	auto t1 = cg.getNodeById(inputs[0])->GetType();
	Value prod( cg.getNodeById(inputs[0])->getValue() );

	if( t1 == INT ) t1 = VECTOR_INT;

	for( size_t i = 1; i < inputs.size(); i++ ) {
		auto t2 = cg.getNodeById(inputs[i])->GetType();
		if( t2 == INT ) t2 = VECTOR_INT;

		if( t1 != t2 ) {
			throw std::logic_error("type mismatch for EvalMult");
		}
		else if( t1 == VECTOR_INT ) {
			prod = cc.EvalMult(prod.GetIntVecValue(), cg.getNodeById( inputs[i] )->getValue().GetIntVecValue());
			t1 = prod.GetType();
		}
		else {
			throw std::logic_error("not implemented");
		}
	}

	return value = prod;
}


}
