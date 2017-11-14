
backends="2 4 6 7"

if [ "$1" != "" ];
then
	backends=$1
fi

for i in $backends
do
	ex=bin/backend-$i/unittest/tests

	echo "****************************"
	echo Testing MATHBACKEND $i
	echo "****************************"
	if [[ -x $ex ]]
	then
		(
			# set paths for mac or linux or win
		export DYLD_LIBRARY_PATH=bin/backend-$i/lib:$DYLD_LIBRARY_PATH
		export LD_LIBRARY_PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
		export PATH=bin/backend-$i/lib:$PATH
		$ex -t
		)
		echo "****************************"
		echo TEST DONE
		echo "****************************"
	else
		echo " ******** $ex for MATHBACKEND $i not found"
	fi
done
