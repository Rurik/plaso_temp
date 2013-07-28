#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2013 The Plaso Project Authors.
# Please see the AUTHORS file for details on individual authors.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Parser for Java Cache IDX files."""
import construct

from plaso.lib import errors
from plaso.lib import event
from plaso.lib import eventdata
from plaso.lib import parser
from plaso.lib import timelib

"""
TODO:
  * 6.02 files did not retain IP addresses. However, the 
    deploy_resource_codebase header field may contain the host IP. This needs
    to be researched further, as that field may not always be present. 6.02
   files will currently return 'Unknown'

  * Parser currently obtains the last_modified_date from Section 1. It should
    also create a second event with the file creation date (from file, or from
    HTTP header "Date" which is stored as a strftime() string)
"""

class JavaIDXEventContainer(event.EventContainer):
  
  DATA_TYPE = 'java:download:idx'

  def __init__(self, idx_version, url, ip_address, last_modified_date): 
    super(JavaIDXEventContainer, self).__init__()
    self.idx_version = idx_version
    self.url = url
    self.ip_address = ip_address
    self.last_modified_date = last_modified_date


class JavaIDXParser(parser.PlasoParser):

  def Parse(self, file_object):
    """
    There are three section structures here. 6.02 files had one generic section
    that retained all data. From 6.03 on, the file went to a multi-section
    format where later sections were optional and had variable-lengths. 6.03,
    6.04, and 6.05 files all have their main data section (#2) begin at offset
    128. The short structure is because 6.05 files deviate after the 8th byte.
    So, grab the first 8 bytes to ensure it's valid, get the file version, then
    restart with the correct structure.
    """
    IDX_SHORT_STRUCT = construct.Struct('magic',
                      construct.UBInt8('busy'),
                      construct.UBInt8('incomplete'),
                      construct.UBInt32('idx_version'),
                      construct.UBInt16('null_space'))

    IDX_602_STRUCT = construct.Struct('LastModDate', 
                      construct.UBInt8('busy'),
                      construct.UBInt8('incomplete'),
                      construct.UBInt32('idx_version'),
                      construct.UBInt16('null_space'),
                      construct.UBInt8('shortcut'),
                      construct.UBInt32('content_length'),
                      construct.UBInt64('last_modified_date'),
                      construct.UBInt64('expiration_date'),
                      construct.Padding(3), 
                      construct.PascalString('url'))

    IDX_603_SECTION1_STRUCT = construct.Struct('LastModDate', 
                      construct.UBInt8('busy'),
                      construct.UBInt8('incomplete'),
                      construct.UBInt32('idx_version'),
                      construct.UBInt16('null_space'),  # removed in 6.05
                      construct.UBInt8('shortcut'),
                      construct.UBInt32('content_length'),
                      construct.UBInt64('last_modified_date'),
                      construct.UBInt64('expiration_date'),
                      construct.UBInt64('validation_date'),
                      construct.UBInt8('signed'),
                      construct.UBInt32('sec2len'),
                      construct.UBInt32('sec3len'),
                      construct.UBInt32('sec4len'))
    
    IDX_605_SECTION1_STRUCT = construct.Struct('LastModDate', 
                      construct.UBInt8('busy'),
                      construct.UBInt8('incomplete'),
                      construct.UBInt32('idx_version'),
                      construct.UBInt8('shortcut'),
                      construct.UBInt32('content_length'),
                      construct.UBInt64('last_modified_date'),
                      construct.UBInt64('expiration_date'),
                      construct.UBInt64('validation_date'),
                      construct.UBInt8('signed'),
                      construct.UBInt32('sec2len'),
                      construct.UBInt32('sec3len'),
                      construct.UBInt32('sec4len'))

    IDX_SECTION2_STRUCT = construct.Struct('Section2',
                      construct.Padding(3), 
                      construct.PascalString('url'),
                      construct.Padding(3),
                      construct.PascalString('ip_address'))
    try:
      magic = IDX_SHORT_STRUCT.parse_stream(file_object)
      idx_version = magic.idx_version
      file_object.seek(0)

      """ 
      magic.busy and magic.incomplete are normally 0x00. They are set to 0x01
      if the file is currently being downloaded. Logic checks for > 1 to avoid
      a race condition and still reject any file with other data.
      """
      if magic.busy > 1 or magic.incomplete > 1:  
        raise errors.UnableToParseFile('[JAVA_IDX] Not a valid Java IDX file')
    except IOError as e:
      raise errors.UnableToParseFile(
          u'[JAVA_IDX] Not a Java IDX file, unable to parse. ',
          u'Reason given: {}'.format(e))

    """ 
    Obtain the last modified date from the file. This date denotes when the
    file was last modified on the HOST. For example, when the file was
    uploaded to a web server.
    """
    if idx_version == 602:
      section1 = IDX_602_STRUCT.parse_stream(file_object)      
      last_modified_date = section1.last_modified_date
    if idx_version in [603, 604]:
      section1 = IDX_603_SECTION1_STRUCT.parse_stream(file_object)
      last_modified_date = section1.last_modified_date
    elif idx_version == 605:
      section1 = IDX_605_SECTION1_STRUCT.parse_stream(file_object)
      last_modified_date = section1.last_modified_date

    """ Obtain URL and IP address from HTTP fields """
    if idx_version == 602:
      url = section1.url
      ip_address = 'Unknown' 
    elif idx_version in [603, 604, 605]:
      file_object.seek(128)  # Static offset for section 2
      section2 = IDX_SECTION2_STRUCT.parse_stream(file_object)
      url = section2.url
      ip_address = section2.ip_address

    if not url or not ip_address:
      raise errors.UnableToParseFile('[JAVA_IDX] Unexpected Error:',
                                     u' URL not found in file')
    yield JavaIDXEventContainer(idx_version, url, ip_address,
                                last_modified_date)
