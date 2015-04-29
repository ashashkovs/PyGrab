__author__ = 'le'

# -*- coding: UTF-8 -*-
from os import listdir
from os.path import isfile
from os.path import join as joinpath
import datetime
import os
import time
import logging
import hashlib
from optparse import OptionParser
from grab import Grab, GrabError
from pyquery import PyQuery as pq
from lxml import etree
from grab import UploadFile

pedumpMapElements = {}
herdprotectMapElements = {}
differenceMap ={}

def params():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', required=True, dest='Path', help="Enter the path to the folder")
    args = parser.parse_args()
    pathFolder= args.Path
    return pathFolder

def grubbingPedump():
    keysInfoTab = ['filename', 'size', 'md5']
    keysPETab = ['LinkerVersion', 'OperatingSystemVersion']
    keysVersionInfoTab = ['CompanyName', 'FileDescription', 'ProductName', 'LegalCopyright', 'ProductVersion']

    for elem in keysInfoTab:
        value = g.doc.pyquery('div#info').find('th:contains("'+elem+'")').next()[0].text_content()
        pedumpMapElements[elem] = value.lower()

    for elem in keysPETab:
        value = g.doc.pyquery('div#pe').find('td:contains("'+elem+'")').next()[0].text_content()
        pedumpMapElements[elem] = value.lower()

    for elem in keysVersionInfoTab:
        value = g.doc.pyquery('div#version-info').find('td:contains("'+elem+'")').next()[0].text_content()
        pedumpMapElements[elem] = value.lower()

    pedumpMapElements['SHA-1'] = hashlib.sha1(open(fileName, 'rb').read()).hexdigest()
    pedumpMapElements['SHA-256'] = hashlib.sha256(open(fileName, 'rb').read()).hexdigest()

    format = '%m/%d/%Y %I:%M:%S %p'
    date_string = time.ctime(os.path.getctime(fileName))
    compilationDate = datetime.datetime.strftime(datetime.datetime.strptime(date_string, "%a %b %d %H:%M:%S %Y"), format)
    pedumpMapElements['CompilationTimestamp'] = compilationDate.lower()

    value = g.doc.pyquery('div#pe').find('td:contains("Subsystem")').next()[1].text_content()
    options = {
        '1': 'Native',
        '2': 'Windows GUI',
        '3': 'Windows Console',
        '5': 'OS/2',
        '6': 'Posix'
    }
    pedumpMapElements['Subsystem'] = options[value].lower()


def grubbingHerdprotect():
    key = ['filename', 'size', 'md5', 'SHA-1', 'SHA-256', 'CompilationTimestamp', 'LinkerVersion', 'OperatingSystemVersion', 'Subsystem', 'CompanyName', 'FileDescription', 'ProductName', 'LegalCopyright', 'ProductVersion',]
    elemKey = ['File name:', 'File size:', 'MD5:', 'SHA-1:', 'SHA-256:', 'Compilation timestamp:', 'Linker version:', 'OS version:', 'Subsystem:', 'Publisher:', 'Description:', 'Product:', 'Copyright:', 'Product version:']

    for i in range(len(key)):
        value = g.doc.pyquery('div.keyvaluepairs div.keyvaluepair').find('div.key:contains("'+elemKey[i]+'")').next()[0].text_content()
        herdprotectMapElements[key[i]] = value.lower()

g = Grab()
g.setup(debug=True)
logger = logging.getLogger('grab')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.DEBUG)
dir = params()
countErrors = 0

if os.path.exists(dir):
    names = os.listdir(dir)
    for name in names:
        fileName = os.path.join(dir, name)  # получаем полное имя файла
        if os.path.isfile(fileName):
            g.go('http://pedump.me')
            g.doc.set_input('file', UploadFile(fileName))
            g.doc.submit()
            if g.response.code == 200:
                grubbingPedump()
                # print pedumpMapElements
                md5 = pedumpMapElements['md5']      # получаем md5 для поиска файла в herdprotect
                g.go('http://www.herdprotect.com/knowledgebase.aspx')
                g.doc.set_input('ctl00$txtSearch', md5)
                g.doc.submit(submit_name='ctl00$cmdSearch')
                g.setup(connect_timeout=10)            # таймаут 10 секунд пока ищется файл в облаке
                grubbingHerdprotect()
                # print herdprotectMapElements
                differenceMap = dict([x for x in pedumpMapElements.items() if x not in herdprotectMapElements.items()])
                countErrors += len(differenceMap)  #считаем количество несоответствий
                if len(differenceMap) != 0 :
                    print "-------------------"
                    print "In file: " + name + " by path: " + g.response.url + " found a " + str(len(differenceMap)) + " discrepancy in the fields: " + str(differenceMap.keys())
                    print "-------------------"

    print "-------------------"
    print "Checked " + str(len(names)) + " files in folder '" + dir + "'\nAll found " + str(countErrors ) + " errors"

else:
    print "File folder not found"
