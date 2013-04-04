image_ripper
============

Extracts jpeg images and PDF documents from a raw disk images

### Summary
Tools like Autopsy can be useful for examining the contents of a disk image offline.

However, that can be cumbersome if there are a large amount of files, and you are only interested in a specific types of file.

This python script uses the sleuth kit to extract all PDFs and images from a disk image, and extracts the information into a SQLite database. A human-readable text report is also generated.

The extracted files are stored in two directories: `overt` and `deleted`.

The text report is stored in `report.txt` (by default) and the full results are stored in `ripper.sqlite` (by default)

### Dependencies
The extraction is done by using utilities from The Sleuth Kit (TSK). 
As such, it needs to be installed on the system that runs the script.

Additionally, it requires SQL Alchemy, PyPDF2 (from https://github.com/colemana/PyPDF2) and EXIF (from https://github.com/ianare/exif-py)
