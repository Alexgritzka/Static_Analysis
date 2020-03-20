#!/bin/bash
for p in $(strings "$1"); do
	$(unzip -tP "$p" "$1" &> /dev/null)
	if [ "$?" = "1" ]; then
		echo "Correct Password is $p"
		exit 1
	fi
done
echo "Could not find password"
exit 0
