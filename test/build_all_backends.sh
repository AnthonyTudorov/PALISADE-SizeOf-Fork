[ "$1" -eq "force" ] && make clean
echo "****************************"
echo Building all backends
echo "****************************"

for i in 2 4 6 7
do
	echo "****************************"
	echo Building and testing MATHBACKEND $i
	echo "****************************"
	[ "$1" -eq "force" ] && touch src/core/lib/math/backend.h
	make -j16  BINDIR=bin/backend-$i CPPFLAGS+=-DMATHBACKEND=$i all benchmark >/dev/null 2>&1
	if [ $? -eq 0 ];
	then
		echo "****************************"
		echo BUILT
		echo "****************************"
	else
		echo " ******** build for MATHBACKEND $i failed!!!"
	fi
done
