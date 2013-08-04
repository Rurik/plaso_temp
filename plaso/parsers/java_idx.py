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

#TODO:
#  * 6.02 files did not retain IP addresses. However, the 
#    deploy_resource_codebase header field may contain the host IP. This needs
#    to be researched further, as that field may not always be present. 6.02
#    files will currently return 'Unknown'
import construct
import time

from plaso.lib import errors
from plaso.lib import event
from plaso.lib import eventdata
from plaso.lib import parser
from plaso.lib import timelib


class JavaIDXEventContainer(event.EventContainer):
  """Convenience class for a Java IDX cache file download container."""
  DATA_TYPE = 'java:download:idx'

  def __init__(self, idx_version, url, ip_address):
    """Initializes the event object.

    Args:
      idx_version: File structure version of IDX file
      url: The URL of the downloaded file.
      ip_address: IP address of the host in the URL.
    """  
    super(JavaIDXEventContainer, self).__init__()
    self.idx_version = idx_version
    self.url = url
    self.ip_address = ip_address


class JavaIDXParser(parser.PlasoParser):
  """Parse Java IDX files for download events."""

  """
  There are five structures defined. 6.02 files had one generic section
  that retained all data. From 6.03 on, the file went to a multi-section
  format where later sections were optional and had variable-lengths. 6.03,
  6.04, and 6.05 files all have their main data section (#2) begin at offset
  128. The short structure is because 6.05 files deviate after the 8th byte.
  So, grab the first 8 bytes to ensure it's valid, get the file version,
  then continue on with the correct structures.

  Note for review: Difference b/w 603 and 605 structure is first two bytes.
  Keep two structs for those bytes, or use one struct and throw away the
  first two bytes for 603 with a `junk = file_object.read(2)`?
  """

  IDX_SHORT_STRUCT = construct.Struct(
    'magic',
    construct.UBInt8('busy'),
    construct.UBInt8('incomplete'),
    construct.UBInt32('idx_version'))

  IDX_602_STRUCT = construct.Struct(
    'IDX_602_Full', 
    construct.UBInt16('null_space'),
    construct.UBInt8('shortcut'),
    construct.UBInt32('content_length'),
    construct.UBInt64('last_modified_date'),
    construct.UBInt64('expiration_date'),
    construct.PascalString('version_string', 
      length_field = construct.UBInt16("length")),
    construct.PascalString('url', 
      length_field = construct.UBInt16("length")),
    construct.PascalString('namespace', 
      length_field = construct.UBInt16("length")),
    construct.UBInt32('FieldCount'))

  IDX_603_SECTION1_STRUCT = construct.Struct(
    'IDX_603_Section1', 
    construct.UBInt16('null_space'),
    construct.UBInt8('shortcut'),
    construct.UBInt32('content_length'),
    construct.UBInt64('last_modified_date'),
    construct.UBInt64('expiration_date'),
    construct.UBInt64('validation_date'),
    construct.UBInt8('signed'),
    construct.UBInt32('sec2len'),
    construct.UBInt32('sec3len'),
    construct.UBInt32('sec4len'))
    
  IDX_605_SECTION1_STRUCT = construct.Struct(
    'IDX_605_Section1', 
    construct.UBInt8('shortcut'),
    construct.UBInt32('content_length'),
    construct.UBInt64('last_modified_date'),
    construct.UBInt64('expiration_date'),
    construct.UBInt64('validation_date'),
    construct.UBInt8('signed'),
    construct.UBInt32('sec2len'),
    construct.UBInt32('sec3len'),
    construct.UBInt32('sec4len'))

  IDX_SECTION2_STRUCT = construct.Struct(
    'Section2',
    construct.PascalString('url', 
      length_field = construct.UBInt32("length")),
    construct.PascalString('ip_address', 
      length_field = construct.UBInt32("length")),
    construct.UBInt32('FieldCount'))

  """ Java uses Pascal-style strings, but with a 2-byte length field. """
  JAVA_READUTF_STRING = construct.Struct(
    'Java.ReadUTF',
    construct.PascalString('string', 
      length_field = construct.UBInt16("length")))

  """ Date/time format for HTTP Date field strings. """
  HTTP_DATE_FMT = "%a, %d %b %Y %H:%M:%S %Z"

  def Parse(self, file_object):
    """
    This is the main parsing engine for the parser. It determines if the 
    selected file is a proper IDX file. It then checks the file version to
    determine the correct structure to apply to extract data.
    """

    try:
      magic = self.IDX_SHORT_STRUCT.parse_stream(file_object)
    except IOError as e:
      raise errors.UnableToParseFile(
          u'[JAVA_IDX] Not a Java IDX file, unable to parse. ',
          u'Reason given: {}'.format(e))

    idx_version = magic.idx_version
    """ 
    magic.busy and magic.incomplete are normally 0x00. They are set to 0x01
    if the file is currently being downloaded. Logic checks for > 1 to avoid
    a race condition and still reject any file with other data.
    """
    if magic.busy > 1 or magic.incomplete > 1:  
      raise errors.UnableToParseFile('[JAVA_IDX] Not a valid Java IDX file')

    """ 
    Obtain the relevant values from the file. The last modified date denotes
    when the file was last modified on the HOST. For example, when the file
    was uploaded to a web server. 
    """
    if idx_version == 602:
      section1 = self.IDX_602_STRUCT.parse_stream(file_object)
      last_modified_date = section1.last_modified_date
      url = section1.url
      ip_address = 'Unknown'
      http_header_count = section1.FieldCount
    elif idx_version in [603, 604]:
      section1 = self.IDX_603_SECTION1_STRUCT.parse_stream(file_object)
      last_modified_date = section1.last_modified_date
      file_object.seek(128)  # Static offset for section 2
      section2 = self.IDX_SECTION2_STRUCT.parse_stream(file_object)
      url = section2.url
      ip_address = section2.ip_address
      http_header_count = section2.FieldCount
    elif idx_version == 605:
      section1 = self.IDX_605_SECTION1_STRUCT.parse_stream(file_object)
      last_modified_date = section1.last_modified_date * 1000
      file_object.seek(128)  # Static offset for section 2
      section2 = self.IDX_SECTION2_STRUCT.parse_stream(file_object)
      url = section2.url
      ip_address = section2.ip_address
      http_header_count = section2.FieldCount

    """
    File offset is now just prior to HTTP headers. Make sure there are
    headers, and then parse them to retrieve the download date.
    """
    for field in range(0, http_header_count):
      field = self.JAVA_READUTF_STRING.parse_stream(file_object)
      value = self.JAVA_READUTF_STRING.parse_stream(file_object)
      if field.string == 'date':
        download_date = timelib.Timestamp.FromTimeString(value.string, 
          self.HTTP_DATE_FMT)

    if not url or not ip_address:
      raise errors.UnableToParseFile('[JAVA_IDX] Unexpected Error:',
                                     ' URL not found in file')
    
    container = JavaIDXEventContainer(idx_version, url, ip_address)

    container.Append(event.TimestampEvent(
      last_modified_date,
      'File Hosted Date',
      container.DATA_TYPE))

    container.Append(event.TimestampEvent(
      download_date,
      eventdata.EventTimestamp.FILE_DOWNLOADED,
      container.DATA_TYPE))

    return container
