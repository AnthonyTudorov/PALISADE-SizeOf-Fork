#include "CircuitNode.h"
#include "CircuitGraph.h"
#include <typeinfo>

int	CircuitNode::generatedNameCounter = 0;

CircuitNode *
CircuitNode::NodeFactory(string op, vector<CircuitNode *>args, string name) {
	if( name == "" ) {
		name = generateNodeName();
	}
	if( op == "EvalNeg" ) return new EvalNegNode(name, args[0]);
	else if( op == "EvalAdd" ) return new EvalAddNode(name, args[0], args[1]);
	else if( op == "EvalMult" ) return new EvalMultNode(name, args[0], args[1]);
	else if( op == "ModReduce" ) return new ModReduceNode(name, args[0]);
	else if( op == "Input" ) return new Input(name);
	else if( op == "Output" ) return new Output(name, args[0]);
	else return 0;
}

ostream& operator<<(ostream& out, const CircuitNode& n)
{
	out << n.name << "  [label=\"";
	if( n.nodeInputDepth != 0 )
		out << "(" + std::to_string(n.nodeInputDepth) + ")\\n";
	out << n.getNodeLabel();
	out << "\\n\\[" << n.getValue() << "\\] \" ";

	out << " xlabel=\"" << n.getNodeDecoration() << "\"]; ";

	const vector<CircuitNode*>& nodeInputs = n.getInputs();
	for( CircuitNode* input : nodeInputs )
		out << input->getName() << " -> " << n.getName() << "; ";
	if( n.is_output ) {
		out << "{ rank=same; Outputs " << n.getName() << " }; ";
	}
	else if( typeid(n) == typeid(Input) ) {
		out << "{ rank=same; Inputs " << n.name << " }; ";
	}

	return out;
}

static bool
insertMRbetween(CircuitGraph *g, CircuitNode *up, CircuitNode *down)
{
	if( down->isModReduce() ) {
		// just expand the thing
		down->setInputDepth(up->getOutputDepth());
		return true;
	}

	string outName = up->getName();
	string inName = down->getName();

	string mrName = outName + "_" + inName;
	CircuitNode *newMR = CircuitNode::NodeFactory("ModReduce", vector<CircuitNode*>({up}), mrName);
	newMR->setInputDepth(up->getOutputDepth());
	newMR->setOutputDepth(down->getInputDepth());

	// replace the old input to down (up) with the new input (newMR)
	bool didChange = false;
	for( int i = 0; i < down->getInputs().size(); i++ ) {
		if( down->getInputs().at(i) == up ) {
			down->setInput(i, newMR);
			didChange = true;
			break;
		}
	}

	if( didChange == false ) {
		throw std::logic_error("something is screwed up; could not find up in down's inputs!");
	}

	// link in the new mod/reduce between up and down
	up->addOutput(mrName);

	// remove inName from out; remove otherOut from inName
	up->delOutput(inName);

	return g->addNode(newMR);
}

void
CircuitNode::processNodeDepth(CircuitGraph *g, queue<CircuitNode *>& nodeQueue)
{
	// calculate what the input depth should be for this node given its output depth
	this->setBottomUpDepth();
	int inDepth = this->getInputDepth();

	// assign new output depth to every node providing input
	for( CircuitNode *in : getInputs() ) {
		// if this node has not been seen yet... set it's output
		if( in->getOutputDepth() == 0 ) {
			in->setOutputDepth(inDepth);
			nodeQueue.push(in);
		}
		else if( in->getOutputDepth() > inDepth ) {
			if( insertMRbetween(g, in, this) == false ) {
				std::cout << "problem inserting mr" << std::endl;
			}
		}
		else if( in->getOutputDepth() < inDepth ) {
			in->resetOutputDepth(inDepth);
			nodeQueue.push(in);

			// now find all the links leaving "in" that might need a mod/reduce

			set<string> otherOutputs(in->getOutputs());
			for( string otherOut : otherOutputs ) {
				CircuitNode *out = g->getNodeByName(otherOut);
				if( out == (CircuitNode *)0 ) {
					std::cout << "There is no node named " + otherOut + " for node " + in->getName() + " in the graph!!" << endl;
					continue;
				}
				int outDepth = out->getInputDepth();

				if( inDepth > outDepth ) {
					if( insertMRbetween(g, in, out) == false ) {
						std::cout << "problem inserting mr" << std::endl;
					}
				} else if( inDepth < outDepth ) {
					std::cout << "Node " << otherOut << " has inputDepth " << outDepth
							<< " and node " << in->getName() << " has outputDepth " << inDepth << std::endl;
				}
			}
		}
//		else if( in->getOutputDepth() == inDepth ) { // do nothing; we are already at the proper depth }
	}
}

void
CircuitNode::processNodeDepth(CircuitGraph *g)
{
	queue<CircuitNode *> items;

	items.push(this);

	while( items.size() > 0 ) {
		items.front()->processNodeDepth(g, items);
		items.pop();
	}
}

