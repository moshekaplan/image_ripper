image_ripper
============

Extracts jpeg images and PDF documents from a raw disk images

The extracted files are stored in two directories: "overt" and "deleted".

A summary of the results are stored in a text file (by default report.txt) and the full results are stored in a sqlite database (by default ripper.sqlite)

The extraction is done by using utilities from the sleuth kit (TSK). 
As such, it needs to be installed on the system that runs the script.

Additionally, it requires SQL Alchemy, PyPDF2 (from https://github.com/colemana/PyPDF2) and EXIF (from https://github.com/ianare/exif-py)
