# Virus-detection-python

Python3 script for virustotal public API

postfile.py : Some python code will hopefully illustrate better how this is done. Since urllib2 cannot (at least up to python 2.5) send files using POST and multipart/form-data encoding we will use this snippet(http://code.activestate.com/recipes/146306/) to help us, let us call it postfile.py

shFind.sh : Find the files that are created in the last second/minute/hour/... in unix 

txtListFile.txt : List files we need to scan (result of shFind.sh)

txtSHA256.txt : List SHA256 (result of pyScan.py)

txtEmail.txt : Email content

pyScan.py : Check files via API (get SHA256)

pyResult.py : Get files status via APT






