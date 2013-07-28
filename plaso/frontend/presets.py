#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2013 The Plaso Project Authors.
# Please see the AUTHORS file for details on individual authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
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
"""Helper file for filtering out parsers."""

categories = {
    'winxp': [
        'ChromeHistoryParser', 'FirefoxHistoryParser', 'GoogleDriveParser',
        'JavaIDXParser', 'MsiecfParser', 'OLECF', 'PfileStatParser',
        'Symantec', 'WinEvtParser', 'WinInfo2Parser', 'WinLnkParser',
        'WinPrefetchParser', 'WinRegistryParser'],
    'winxp_slow': [
        'ChromeHistoryParser', 'FirefoxHistoryParser', 'GoogleDriveParser',
        'JavaIDXParser', 'Hachoir', 'MsiecfParser', 'OLECF', 'PfileStatParser',
        'Symantec', 'WinEvtParser', 'WinInfo2Parser', 'WinLnkParser',
        'WinPrefetchParser', 'WinRegistryParser'],
    'win7': [
        'ChromeHistoryParser', 'FirefoxHistoryParser', 'GoogleDriveParser',
        'JavaIDXParser', 'MsiecfParser', 'OLECF', 'PfileStatParser',
        'Symantec', 'WinEvtxParser', 'WinLnkParser', 'WinPrefetchParser',
        'WinRecycleParser', 'WinRegistryParser'],
    'win7_slow': [
        'ChromeHistoryParser', 'FirefoxHistoryParser', 'GoogleDriveParser',
        'JavaIDXParser', 'Hachoir', 'MsiecfParser', 'OLECF', 'PfileStatParser',
        'Symantec','WinEvtxParser', 'WinLnkParser', 'WinPrefetchParser',
        'WinRecycleParser', 'WinRegistryParser'],
    'webhist': [
        'ChromeHistoryParser', 'FirefoxHistoryParser', 'JavaIDXParser',
        'MsiecfParser'],
    'linux': [
        'ChromeHistoryParser', 'FirefoxHistoryParser', 'GoogleDriveParser',
        'JavaIDXParser', 'OLECF', 'PfileStatParser', 'SELinux',
        'SyslogParser'],
    'macosx': [
        'ApplicationUsageParser', 'ChromeHistoryParser',
        'FirefoxHistoryParser', 'GoogleDriveParser', 'JavaIDXParser',
        'LsQuarantineParser', 'OLECF', 'PfileStatParser', 'PlistParser',
        'SyslogParser'],
}
