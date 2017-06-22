PC=bin/demo/circuit/palcircuit
GT=bin/demo/circuit/gentimingest

filename=`basename $1`
fn="${filename%.*}"

$PC -v -gproc=${fn}.proc.dot -elist=${fn}.listfile $1
$GT ${fn}.listfile ${fn}.statsfile
$PC -gresult=${fn}.result.dot -estats=${fn}.statsfile $1
