#!/usr/bin/env python
# Encoding: utf-8
"""
Your task will be to create a python script that extracts image and pdf files from a forensic image.
We will limit this test to extraction from the 2 images referenced below.
This means that I will grade you on your ability to extract from the 2 images referenced.

(50 points) Create a python script that extracts images and pdf’s - complete
(10 points) Include the ability to extract deleted images - complete
(10 points) Include the ability to extract deleted pdf’s - complete
(5 points ) Extract files to 2 subfolders (overt & deleted) - complete
(5 points ) Calculate MD5 of each file extracted - complete
(5 points ) Extract exif\meta data for each file found - complete
(5 points ) Extract file system information (ntfs, fat16, fat32, etc) + disk offset + size of recovered files - complete
(5 points ) Produce a sqlite database with all information found for each file (hash, exif, meta, etc) - complete
(5 points ) Produce a report with all the information found (any format ­ txt, html, etc) - complete

Written by Moshe Kaplan
Copyright 2013

Notes:
This script uses the Sleuth Kit (TSK) to extract the files from a disk image.
As such, it requires that TSK be installed.

It also requires that file be installed, as it is used to determine the filetype of an image.
"""

# Built-in modules
import os
import sys
import hashlib
import argparse
import subprocess

# SQL Alchemy
from sqlalchemy import Column, Boolean, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

# Available from https://github.com/colemana/PyPDF2
import PyPDF2

# Available from https://github.com/ianare/exif-py
import EXIF

###############################################################################
# Utils
###############################################################################

def get_result_from_subprocess(cmd):
  p = subprocess.Popen(args=cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  out, err = p.communicate()
  return out

###############################################################################
# Disk-image utils
###############################################################################

# Uses fls to get all undeleted files:
def fls_get_undeleted(img_name):
  return "fls -F -p -r -u".split() + [img_name]

# Uses fls to get all deleted files:
def fls_get_deleted(img_name):
  return  "fls -F -p -r -d".split() + [img_name]

# Use icat to retrieve a file from the image
def icat_get_file(img_name, node):
  return ["icat", img_name, node]

# Use fsstat to get filesystem info
def fsstat_get_type(img_name):
  return "fsstat -t".split() + [img_name]

def fsstat_get_details(img_name):
  return ["fsstat", img_name]

def get_nodes_from_fls(fls_command):
  result = get_result_from_subprocess(fls_command)
  entries = []
  for line in result.split('\n'):
    if not line:
      continue
    
    entry_type, remaining = line.split(' ', 1)
    location, fname = remaining.split('\t', 1)
    # Remove the trailing colon and a (possibly) leading asterisk
    location = location[:-1].split()[-1]
    entry = {'location':location, 'fname':fname}
    entries.append(entry)
  return entries
  
def get_all_nodes(img_name):
  cmd = fls_get_deleted(img_name)
  deleted = get_nodes_from_fls(cmd)

  cmd = fls_get_undeleted(img_name)
  undeleted = get_nodes_from_fls(cmd)
  return undeleted, deleted

def extract_file(img_name, node, destination):
  cmd = icat_get_file(img_name=img_name, node=node)
  data = get_result_from_subprocess(cmd)
  with open(destination, 'wb') as fh:
    fh.write(data)
  

def extract_all_files(img_name, entries, destination, delete_other=True):
  # Takes a list of node/fname dictionaries and stores them in destination
  if not os.path.isdir(destination):
      os.makedirs(destination)
  
  all_results = []
  for entry in entries:
    result = {}
    result['original_path'] = entry['fname']
    result['location'] = entry['location']

    # This is convoluted because entry['fname'] can include /
    full_path = os.path.join(destination, entry['fname'])
    path, fname = os.path.split(full_path)
    final_destination = os.path.join(destination, fname)
    result['final_destination'] = final_destination
    
    extract_file(img_name, entry['location'], final_destination)
    result['size'] = os.path.getsize(final_destination)
    result['md5'] = get_md5(final_destination)
    file_type = get_file_type(final_destination)
    
    result['file_type'] = file_type
    
    # As a small cleanup: If it's not an image or pdf, delete it.
    if delete_other and file_type == 'other':
      os.remove(final_destination)
      result['final_destination'] = None
  
    all_results.append(result)
  return all_results

def get_disk_type(img_name):
  cmd = fsstat_get_type(img_name=img_name)
  return get_result_from_subprocess(cmd)
  
def get_disk_details(img_name):
  cmd = fsstat_get_details(img_name=img_name)
  return get_result_from_subprocess(cmd)
    
###############################################################################
# File utils
###############################################################################

def file_get_type(fname):
  return "file -b".split() + [fname]

def get_file_type(fname):
  cmd = file_get_type(fname=fname)
  result = get_result_from_subprocess(cmd)
  if result.startswith('PDF'):
    return 'pdf'
  else:
    for magic in ['JPEG', 'PNG', 'GIF','TIFF', 'PC bitmap']:
      if result.startswith(magic):
        return 'image'
  return 'other'

def get_md5(fname):
    """Returns the MD5 hash for a file"""
    with open(fname, 'rb') as fh:
        data = fh.read()
        md5 = hashlib.md5(data).hexdigest()
        return md5

def get_pdf_metadata(fname):
  with open(fname, 'rb') as fh:
    pdf = PyPDF2.PdfFileReader(fh)
    return pdf.getDocumentInfo()
  
  
def get_exif_data(fname):
  with open(fname, 'rb') as fh:
    return EXIF.process_file(fh)

###############################################################################
# Sqlite
###############################################################################

Base = declarative_base()

class ImageInfo(Base):
    __tablename__ = 'image_info'
    id = Column(Integer, primary_key = True)
    fs_type = Column(String)
    path = Column(String)
    total_recovered_size = Column(Integer)
    total_useful_size = Column(Integer)
    full_info = Column(String)
    
    def __init__(self, path, fs_type, total_recovered_size, total_useful_size, full_info):
        self.path  = path
        self.fs_type = fs_type
        self.total_recovered_size = total_recovered_size
        self.total_useful_size = total_useful_size
        self.full_info = full_info

class FileInfo(Base):
    __tablename__ = 'file_info'
    id = Column(Integer,primary_key = True)
    file_type = Column(String)
    file_metadata  = Column(String)
    original_path = Column(String)
    final_destination = Column(String)
    location = Column(String)
    size = Column(Integer)
    md5 = Column(String)
    deleted = Column(Boolean)
    img_src = Column(Integer, ForeignKey('image_info.id'))
    img = relationship("ImageInfo", backref='files', lazy=False)

    def __init__(self, file_type, file_metadata, original_path, final_destination, location, size, md5, deleted):
        self.file_type = file_type
        self.file_metadata  = str(file_metadata).decode('utf-8')
        self.original_path = str(original_path).decode('utf-8')
        self.final_destination = str(final_destination).decode('utf-8')
        self.location = str(location).decode('utf-8')
        self.size = size
        self.md5 = md5
        self.deleted = deleted
        
def save_sql(db_name, img_name, filesystem_type, filesystem_info, total_file_size, 
                total_useful_size, deleted_results, overt_results):
    engine = create_engine('sqlite:///%s' % db_name, echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # First add the image information
    img = ImageInfo(img_name, filesystem_type, total_file_size, 
                    total_useful_size, filesystem_info)
    
    session.add(img)
    session.commit()
    
    for entry in overt_results:
        file_entry = FileInfo(deleted=False, **entry)
        file_entry.img = img
        session.add(file_entry)
        session.commit()
    for entry in deleted_results:
        file_entry = FileInfo(deleted=True, **entry)
        file_entry.img = img
        session.add(file_entry)
        session.commit()

###############################################################################
# Reports
###############################################################################

def create_report(fname, img_name, filesystem_type, filesystem_info, total_file_size, 
                total_useful_size, deleted_results, overt_results):
    with open(fname, 'w') as report:
        report.write("*"*80 + '\n')
        report.write("Here is the information for {img_name}:\n".format(img_name=img_name))
        report.write("Filesystem type: %s\n" % filesystem_type)
        report.write("Total recovered size: %d\n" % total_file_size)
        report.write("Total useful size: %d\n" % total_useful_size)

        report.write("*"*80 + '\n')
        report.write("Filesystem info:\n")
        report.write(filesystem_info + '\n')

        report.write("*"*80 + '\n')
        report.write("File info:\n")
        for entry in overt_results:
            for k,v in entry.iteritems():
                report.write("%s: %s\n" % (k, v))
            report.write('\n')
    
        report.write("*"*80 + '\n')
        report.write("Deleted file info:\n")
        for entry in deleted_results:
            for k,v in entry.iteritems():
                report.write("%s: %s\n" % (k, v))
            report.write('\n')
            
###############################################################################
# Main
###############################################################################

DEFAULT_OUTPUT = 'output'
DEFAULT_DB_NAME = "ripper.sqlite"
DEFAULT_REPORT_NAME = 'report.txt'

def build_argparser():
  parser = argparse.ArgumentParser(description="Extracts images and PDF's from a disk iamge")

  # Report filename  
  parser.add_argument('--report', dest='report', action='store',
                      default=DEFAULT_REPORT_NAME,
                      help='Filename used for the report (default is %s)' % DEFAULT_REPORT_NAME)
                      
  # DB filename
  parser.add_argument('--db', dest='db', action='store',
                      default=DEFAULT_DB_NAME,
                      help='Filename used for the database (default is %s)' % DEFAULT_DB_NAME)

  # Output dir
  parser.add_argument('--output', dest='output', action='store',
                      default=DEFAULT_OUTPUT,
                      help='Directory used for the database (default is %s)' % DEFAULT_OUTPUT)

  # Image to examine (required)
  parser.add_argument(dest='img_fname', help='The image to examine')
  return parser
     
def main():
  # Parse the command-line options
  parser = build_argparser()
  args = parser.parse_args(sys.argv[1:])

  img_name = args.img_fname
  output = args.output
  db_name = os.path.join(output, args.db)
  report_fname = os.path.join(output, args.report)
  
  filesystem_type = get_disk_type(img_name)
  filesystem_info = get_disk_details(img_name)
  
  undeleted, deleted = get_all_nodes(img_name)
  
  overt_dest = os.path.join(output, 'overt')
  deleted_dest = os.path.join(output, 'deleted')
  
  overt_results = extract_all_files(img_name, undeleted, overt_dest)
  deleted_results = extract_all_files(img_name, deleted, deleted_dest)
  
  # Now we have two directories filled with image and pdf files.
  
  # Let's get the sizes:
  total_file_size = 0
  total_useful_size = 0
  for entry in deleted_results:
    total_file_size += entry['size']
    if entry['file_type'] != 'other':
      total_useful_size += entry['size']
  for entry in overt_results:
    total_file_size += entry['size']
    if entry['file_type'] != 'other':
      total_useful_size += entry['size']

  # Get the metadata (if possible)
  for entry in overt_results:
    path = entry['final_destination']
    entry['file_metadata'] = None
    try:
      if entry['file_type'] == 'pdf':
        entry['file_metadata'] = get_pdf_metadata(path)
      elif entry['file_type'] == 'image':
        entry['file_metadata'] = get_exif_data(path)
    except:
      pass
  
  for entry in deleted_results:
    path = entry['final_destination']
    entry['file_metadata'] = None
    try:
      if entry['file_type'] == 'pdf':
        entry['file_metadata'] = get_pdf_metadata(path)
      elif entry['file_type'] == 'image':
        entry['file_metadata'] = get_exif_data(path)
    except:
      pass
  
  # Create the report:
  
  create_report(report_fname, img_name, filesystem_type, filesystem_info, total_file_size, 
                total_useful_size, deleted_results, overt_results)
  
  # And save the data to a sqlite db
  save_sql(db_name, img_name, filesystem_type, filesystem_info, total_file_size, 
                total_useful_size, deleted_results, overt_results)
  
if __name__ == "__main__":
  main()
