#include "CircuitNode.h"
#include "CircuitGraph.h"
#include <typeinfo>

ostream& operator<<(ostream& out, const CircuitNode& n)
{
	out << n.nodeId << "  [label=\"";
	if( n.nodeInputDepth != 0 )
		out << "(" + std::to_string(n.nodeInputDepth) + ")\\n";
	out << n.getNodeLabel();
	out << "\\n\\[" << n.getValue() << "\\] \" ";

	out << " xlabel=\"" << n.GetId() << "\"]; ";

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

