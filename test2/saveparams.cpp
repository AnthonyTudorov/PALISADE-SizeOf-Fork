#include "saveparams.h"

Params::Params() {}
//Json set-methods
void Params::set_PlaintextModulus(string const &PlaintextModulus) {PlaintextModulus_=PlaintextModulus;}
void Params::set_DistributionParameter(string const &DistributionParameter) {DistributionParameter_=DistributionParameter;}
void Params::set_AssuranceMeasure(string const &AssuranceMeasure) {AssuranceMeasure_=AssuranceMeasure;}
void Params::set_SecurityLevel(string const &SecurityLevel) {SecurityLevel_=SecurityLevel;}
void Params::set_RelinWindow(string const &RelinWindow) {RelinWindow_=RelinWindow;}
void Params::set_Depth(string const &Depth) {Depth_=Depth;}
//Json get-methods
const string& Params::get_PlaintextModulus() const{return PlaintextModulus_;}
const string& Params::get_DistributionParameter() const{return DistributionParameter_;}
const string& Params::get_AssuranceMeasure() const{return AssuranceMeasure_;}
const string& Params::get_SecurityLevel() const{return SecurityLevel_;}
const string& Params::get_RelinWindow() const{return RelinWindow_;}
const string& Params::get_Depth() const{return Depth_;}

Json::Value Params::ToJson() const{
	Json::Value value(Json::objectValue);
	value["PlaintextModulus"] = PlaintextModulus_;
	value["DistributionParameter"] = DistributionParameter_;
	value["AssuranceMeasure"] = AssuranceMeasure_;
	value["SecurityLevel"] = SecurityLevel_;
	value["RelinWindow"] = RelinWindow_;
	value["Depth"] = Depth_;
	return value;
}

AllParams::AllParams() {params_= vector<Params>();}
const vector<Params>& AllParams::params() const { return params_;}

void AllParams::AddParams(	string const &PlaintextModulus,
				string const &DistributionParameter,
				string const &AssuranceMeasure,
				string const &SecurityLevel,
				string const &RelinWindow,
				string const &Depth) 
	{
	Params ParamObj = Params();
	ParamObj.set_PlaintextModulus(PlaintextModulus);
	ParamObj.set_DistributionParameter(DistributionParameter);
	ParamObj.set_AssuranceMeasure(AssuranceMeasure);
	ParamObj.set_SecurityLevel(SecurityLevel);
	ParamObj.set_RelinWindow(RelinWindow);
	ParamObj.set_Depth(Depth);
	params_.push_back(ParamObj);
	}

void AllParams::JsonSave(const char* filename){
ofstream out(filename,ofstream::out);
Json::Value JsonData(Json::objectValue), params_json(Json::arrayValue);
for(vector<Params>::iterator i = params_.begin();i != params_.end();++i)
{params_json.append((*i).ToJson());}
JsonData["CryptoParams"]=params_json;
out << JsonData;
out.close();
}

void AllParams::JsonLoad(const char* filename){
ifstream in(filename);
Json::Value JsonData;
in >> JsonData;
for(Json::Value::iterator i=JsonData["CryptoParams"].begin(); i!= JsonData["CryptoParams"].end();++i)
{AddParams((*i)["PlaintextModulus"].asString(),(*i)["DistributionParameter"].asString(),(*i)["AssuranceMeasure"].asString(),(*i)["SecurityLevel"].asString(),(*i)["RelinWindow"].asString(),(*i)["Depth"].asString());}
in.close();
}
