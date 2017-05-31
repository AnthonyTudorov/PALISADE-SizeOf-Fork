#include "circuitnode.h"
#include "circuitgraph.h"
#include <typeinfo>

ostream& operator<<(ostream& out, const CircuitNode& n)
{
	out << n.nodeId << "  [label=\"";
	if( n.nodeInputDepth != 0 )
		out << "(" + std::to_string(n.nodeInputDepth) + ")\\n";
	out << n.getNodeLabel() << "\"";
	const Value& val = n.getValue();
	if( val != NULL )
		out << "\\n\\[" << n.getValue()->GetElement() << "\\] \" ";

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

