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

"""Parser for Java IDX download files."""
import os
import pytz
import unittest

from plaso.formatters import java_idx
from plaso.parsers import java_idx
from plaso.lib import preprocess

class IDXTest(unittest.TestCase):

  def setUp(self):
    pre_obj = preprocess.PlasoPreprocess()
    pre_obj.zone = pytz.UTC
    self.test_parser = java_idx.JavaIDXParser(pre_obj)


  def testParseFile(self):
    print '[JAVA_IDX] Testing 6.05 IDX file'
    test_file = os.path.join('test_data', 'java.idx')
    events = None
    with open(test_file, 'rb') as file_object:
      events = list(self.test_parser.Parse(file_object))
    
    # Start testing
    self.assertEquals(len(events), 1)
    event_object = events[0]

    idx_version_expected = 605
    self.assertEquals(event_object.idx_version, idx_version_expected)

    ip_address_expected = '10.7.119.10'
    self.assertEquals(event_object.ip_address, ip_address_expected)

    url_expected = 'http://xxxxc146d3.gxhjxxwsf.xx:82/forum/dare.php?' + \
                   'hsh=6&key=b30xxxx1c597xxxx15d593d3f0xxx1ab'
    self.assertEquals(event_object.url, url_expected)

    last_modified_date_expected = 996123600000
    self.assertEquals(event_object.last_modified_date, 
                      last_modified_date_expected)

    #SECOND TEST, 6.02 file
    print '[JAVA_IDX] Testing 6.02 IDX file'
    test_file = os.path.join('test_data', 'java_602.idx')
    events = None
    with open(test_file, 'rb') as file_object:
      events = list(self.test_parser.Parse(file_object))
    
    # Start testing
    self.assertEquals(len(events), 1)
    event_object = events[0]

    idx_version_expected = 602
    self.assertEquals(event_object.idx_version, idx_version_expected)

    ip_address_expected = 'Unknown'
    self.assertEquals(event_object.ip_address, ip_address_expected)

    url_expected = 'http://www.gxxxxx.com/a/java/xxz.jar'
    self.assertEquals(event_object.url, url_expected)

    last_modified_date_expected = 1273023259720
    self.assertEquals(event_object.last_modified_date, 
                      last_modified_date_expected)

if __name__ == '__main__':
  unittest.main()
