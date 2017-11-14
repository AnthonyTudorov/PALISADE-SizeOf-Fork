for i in 2 4 6 7
do
	lib=bin/backend-${i}-cov/lib
	ex=bin/backend-${i}-cov/unittest/tests

	echo "****************************"
	echo Coverage test MATHBACKEND $i
	echo "****************************"
	if [[ -x $ex ]]
	then
		(
			# set paths for mac or linux or win
		export DYLD_LIBRARY_PATH=$lib:$DYLD_LIBRARY_PATH
		export LD_LIBRARY_PATH=$lib:$LD_LIBRARY_PATH
		export PATH=$lib:$PATH
		$ex -t
		)
		echo "****************************"
		echo TEST DONE
		echo "****************************"
	else
		echo " ******** $ex for MATHBACKEND $i not found"
	fi
done
