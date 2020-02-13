## SAKv2
Version: 2.0.0  
License: GNU General Public License v2.0
Notes: I've written my own subdomain enumerator to replace the sublist3r code I was using, has different sources and yields more results quickly. 

#### About
A subdomain enumeration and enrichment script. Enriches enumerated subdomains from a TLD or list of TLD's with ASN data and Shodan data. Also accepts a list of subdomains to add enrichment to.

#### Prerequisites:
- Python 3 or greater
    > - debian: `sudo apt install python3`  
    > - arch: `sudo pacman -S python`  
    > - windows: `download and install exe`  
- pip
    > - debian: `sudo apt install python-pip`  
    > - arch: `sudo pacman -S python-pip`  
    > - windows: `curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py`, `python get-pip.py`  
- pipenv
    > - linux: `pip install pipenv --user`  
    > - windows: `python -m pip install pipenv --user`  
- pyinstaller (optional for build)
    > - linux: `pip install pyinstaller --user`  
    > - windows: `python -m pip install pyinstaller --user`  
    > - For python3.8: `pip install https://github.com/pyinstaller/pyinstaller/archive/develop.tar.gz --user`  

#### To install: 
1. Change python version in `Pipfile`
2. Install with:
    > - linux: `pipenv install`  
    > - windows: `python -m pipenv install`  
3. Run with:
    > - linux:  `pipenv run sakv2 <options>`  
    > - windows: `python -m pipenv run sakv2 <options>`  
*For Shodan functionality add API key to sakv2/config.ini

#### To build (optional):
1. Follow steps 1 & 2 of install  
    2a.Linux:  
    > 1. Add pyinstaller binary to PATH  
    > 2. Change Python verion in build.sh script  
    > 3. Run `./build.sh`   
    > 4. Script and config are located in `dist`   
    > 5. Run script with `./sakv2 <options>`  

    2b.Windows:  
    > 1. Locate pyinstaller binary  
    > 2. Get venv path with `python -m pipenv --venv`  
    > 3. Run `<pyinstaller binary> sakv2/__main__.py -n sakv2 -p <venv path>\python<version>\site-packages\ -p sakv2\ --onefile` 
    > 4. Script and config are located in `dist`  
    > 5. Run script with `sakv2.exe <options>`  
*For Shodan functionality add API key to dist/config.ini  

#### Usage:
usage: sakv2 -t example.com -11  
The OSINT swiss army knife, Fetches data for TLDs. 

Required arguments (-t or -f):  
>  -t TARGET      A target TLD.  
>  -f TARGETFILE  A target file that contains a list of TLDs.  
>  -o OUTPUT      Outputs to a csv.  

Optional arguments:  
>  -s             Use for inputing a list of subdomains.  
>  -td THREADS    Specify number of threads used (defaults to 40).  
>  -11            Choose this option to enable all modules.  
>  -as            This option enables the ASN data module.  
>  -sh            This option enables the Shodan data module.  

#### Examples:
- pipenv run sakv2 -t example.com -11 -o test.csv
- ./sakv2 -t example.com -as -o test.csv
