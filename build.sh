#!/bin/bash
VENVPATH="$(pipenv --venv)"
PKGPATH="/lib/python3.8/site-packages/"
FULLPATH=${VENVPATH}${PKGPATH}

pyinstaller sakv2/__main__.py -n sakv2 -p ${FULLPATH} -p sakv2/ --onefile &&
rm build/ sakv2.spec -rf &&

printf "\n"

if [ ! -e $1 ]; then
    printf "[config]\nshodankey=$1\n" >> dist/config.ini
else
    printf "[config]\nshodankey=\n" >> dist/config.ini
    printf "Put Shodan API key in ./dist/config.ini\n"
fi
