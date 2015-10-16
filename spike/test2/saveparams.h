#pragma once
#include <string>
#include <vector>
#include <fstream>
#include "../../include/json/json.h"

using namespace std;

class Params {
private:
	string PlaintextModulus_;
	string DistributionParameter_;
	string AssuranceMeasure_;
	string SecurityLevel_;
	string RelinWindow_;
	string Depth_;
public:
	Params();
	void set_PlaintextModulus(string const &PlaintextModulus);
	void set_DistributionParameter(string const &DistributionParameter);
	void set_AssuranceMeasure(string const &AssuranceMeasure);
	void set_SecurityLevel(string const &SecurityLevel);
	void set_RelinWindow(string const &RelinWindow);
	void set_Depth(string const &Depth);


	const string& get_PlaintextModulus() const;
	const string& get_DistributionParameter() const;
	const string& get_AssuranceMeasure() const;
	const string& get_SecurityLevel() const;
	const string& get_RelinWindow() const;
	const string& get_Depth() const;
	
	Json::Value ToJson() const;	
};


class AllParams{
private:
	vector<Params> params_;
public:
	AllParams();
	const vector<Params>& params() const;

	void AddParams(	string const &PlaintextModulus,
			string const &DistributionParameter,
			string const &AssuranceMeasure,
			string const &SecurityLevel,
			string const &RelinWindow,
			string const &Depth);
	const vector<Params>::iterator& begin();
	const vector<Params>::iterator& end();	

	void JsonSave(const char* filename);
	void JsonLoad(const char* filename);
};


