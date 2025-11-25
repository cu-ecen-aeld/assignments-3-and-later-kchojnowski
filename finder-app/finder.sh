#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Wrong args"
  exit 1
fi

if [ ! -d $1 ]; then
  echo "Not dir"
  exit 1
fi

filesdir=$1
searchstr=$2

filescount=$(find ${filesdir} -type f | wc -l)
linescount=$(find ${filesdir} -type f | xargs grep ${searchstr} | wc -l)

echo "The number of files are ${filescount} and the number of matching lines are ${linescount}"
