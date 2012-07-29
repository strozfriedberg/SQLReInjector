"""
Copyright (C) 2012 Stroz Friedberg, LLC

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the license, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

A copy of the GNU Lesser General Public License is available at <http://www.gnu.org/licenses/>.

You can contact Stroz Friedberg by electronic and paper mail as follows:

    Stroz Friedberg, LLC
    32 Avenue of the Americas
    4th Floor 
    New York, NY, 10013

    info@strozfriedberg.com
    
"""

import argparse
import sqlite3
import apachelog
import os
import sys
import urllib2
import difflib
import re

## checkArgs - Reviews the input arguments, makes sure that they exist (as appropriate) and returns error messages otherwise.
def checkArgs(inLog, dbFile, website, compareToGood, knownGood, logFormat):
    if not inLog:
        return "No input log passed"
    elif not os.path.isfile(inLog):
        return "%s does not exist" % (inLog)
    elif not dbFile:
        return "No database file passed"
    elif not website:
        return "No website passed"
    elif not logFormat:
        return "No log format passed"
    elif compareToGood:
        if not knownGood:
            return "No known good website passed"
        elif not os.path.isfile(knownGood):
            return "%s does not exist" % knownGood
        else:
            return False
    else:
        return False

## havijParse -- Take the output of a known set of havij sql injections and generate the table as displayed by havij
def havijParse(cur,con):
    cur.execute("select id, request, returnVal from sqlInjectedReturns")
    havijData = {}
    for row in cur.fetchall():
        if "~" in row['returnVal'] and 'from' in row['request'] and 'limit' in row['request']:
            exfilData = row['returnVal'].split("~")[1]

            #Typical request is GET someurl?id=havijattackstring
            #Use the below two splits to get the havijattackstring
            exfilRequest = row['request'].split(" ")[1]
            exfilRequest = exfilRequest.split("?")[1]

            

            exfilRequest = exfilRequest.split("+")
            exfilTable = exfilRequest[exfilRequest.index("from")+1]
            exfilTable = exfilTable.replace("%60","_")
            exfilTable = exfilTable.replace(".","_")

            for requestPart in exfilRequest:
                if 'concat' in requestPart:
                    exfilRow = requestPart
                    break

            exfilRow = exfilRow[exfilRow.rfind("%28")+3:]
            exfilRow = exfilRow.replace(".","_")

           for toReplace in ['0x27','%2C','0x7e','%29']:
                if toReplace in exfilRow:
                    exfilRow = exfilRow.replace(toReplace,'')

            exfilLimit = exfilRequest[exfilRequest.index("limit")+1]
            if not exfilTable in havijData:
                havijData[exfilTable] = {}
            if not exfilLimit in havijData[exfilTable]:
                havijData[exfilTable][exfilLimit] = {}
            havijData[exfilTable][exfilLimit][exfilRow] = exfilData
    cur.execute("select * from sqlite_master")
    tblNames = set()
    for row in cur.fetchall():
        tblNames.add(row['name'])
    for tblName in tblNames:
        if "havij" in tblName:
            cur.execute("DROP TABLE " + tblName)

    exfilRows = {}

    for exfilTable in havijData:
        if exfilTable not in exfilRows:
            exfilRows[exfilTable] = set()
        for exfilLimit in havijData[exfilTable]:
            for exfilRow in havijData[exfilTable][exfilLimit]:
                exfilRows[exfilTable].add(exfilRow)

    for exfilTable in exfilRows:
        createStmt = "CREATE TABLE havij_" + exfilTable + " ("
        for exfilRow in exfilRows[exfilTable]:
            createStmt += exfilRow + " TEXT,"
        createStmt = createStmt[:-1]+ ", havij_Limit TEXT)"
        cur.execute(createStmt)
    
    for exfilTable in havijData:
        insertStmt = "INSERT INTO havij_" + exfilTable+ " (havij_Limit, "
        for exfilRow in exfilRows[exfilTable]:
            insertStmt += exfilRow + ", "
        insertStmt = insertStmt[:-2] + ") VALUES (" + "?,"*(len(exfilRows[exfilTable])+1)
        insertStmt = insertStmt[:-1] + ")"
        for exfilLimit in havijData[exfilTable]:
            insertRow = [exfilLimit]
            for exfilRow in exfilRows[exfilTable]:
                if exfilRow in havijData[exfilTable][exfilLimit]:
                    insertRow.append(havijData[exfilTable][exfilLimit][exfilRow])
                else:
                    insertRow.append(None)
            cur.execute(insertStmt, insertRow)
        con.commit()
        print "Committed for table %s" % exfilTable
            


def run(inLog, dbFile, website,havijParser,compareToGood, knownGood, cookie, logFormat=""):
##    logFormat = r"%h %l %u %t \"%r\" %>s %b"
    apacheParser = apachelog.parser(logFormat)
    inLogFd = open(inLog)
    lineCounter = 1

    con = sqlite3.connect(dbFile)
    con.row_factory = sqlite3.Row
    con.text_factory = str
    cur = con.cursor()
    cur.execute("select * from sqlite_master")
    dropTable = False
    for row in cur.fetchall():
        if row['name'] == 'sqlInjectedReturns':
            dropTable = True
    if dropTable:
            cur.execute("DROP TABLE sqlInjectedReturns")
    cur.execute("CREATE TABLE IF NOT EXISTS sqlInjectedReturns(id INTEGER PRIMARY KEY AUTOINCREMENT,\
                                                               request TEXT,\
                                                               returnVal TEXT)")

    for line in inLogFd:
        try:
            lineData = apacheParser.parse(line)
        except:
            print "Could not parse data on line %s, error: %s" % (line, sys.exc_info())
            lineCounter += 1
            continue
        urlToGet = website + lineData['%r'].split(" ")[1]
        urlHeaders = {}
        if '%{User-Agent}i' in lineData:
            urlHeaders['User-Agent'] = lineData['%{User-Agent}i']

        if cookie:
            urlHeaders['Cookie']=cookie

        try:
            urlRequest = urllib2.Request(urlToGet, None, urlHeaders)
            urlGetter = urllib2.urlopen(urlRequest)
            urlData = urlGetter.read()
            cur.execute("INSERT INTO sqlInjectedReturns(request, returnVal) Values (?,?)", [lineData['%r'], urlData])
        except:
            print "Could not get data for url %s" % (urlToGet)
        lineCounter += 1
        if lineCounter % 100 == 0:
            print "Parsed %s lines" % (lineCounter)

    con.commit()
    inLogFd.close()
    
    if havijParser:
        print "Parsing Havij attack"
        havijParse(cur, con)
    
    if knownGood:
        print "Comparing to known good"
        compareSqliToGood(cur,con,knownGood)

    con.close()

def compareSqliToGood(cur,con,knownGood):
    kgFd = open(knownGood, 'rb')
    kgData = kgFd.read()
    kgFd.close()

    cur.execute("CREATE TABLE IF NOT EXISTS comparedData(sqliKey INTEGER, diffedData TEXT)")
    cur.execute("DELETE FROM comparedData")

    diffDataDict = {}

    kgDiffer = difflib.Differ()

    cur.execute("SELECT id, returnVal FROM sqlInjectedReturns")
    for row in cur.fetchall():
        diffData = list(kgDiffer.compare(kgData.splitlines(1),row['returnVal'].splitlines(1)))
        for diffLine in diffData:
            if diffLine[0] == " ":
                continue
            elif diffLine[0] == "+":
                if row['id'] not in diffDataDict:
                    diffDataDict[row['id']] = []
                diffDataDict[row['id']].append(diffLine)
    for id in diffDataDict:
        cur.execute("INSERT INTO comparedData(sqliKey, diffedData) VALUES (?,?)", [id, "".join(diffDataDict[id])])
    con.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Replay an SQL injection attack from logs")
    parser.add_argument("-i","--inLog",default=None, help = "Input appache log file parse")
    parser.add_argument("-d","--dbFile",dest="dbFile",default = None, help = "Database log file to write out to")
    parser.add_argument("-w","--website",dest="website",default = None, help = "Website to run against. Form of http://hostname")
    parser.add_argument("-j","--havijParser",dest="havijParser",default=False,action='store_true',help="Parse the returned data to reassemble Havij output")
    parser.add_argument("-c","--compareToGood",dest="compareToGood",default=False,action='store_true',help="Compare the returned data to a known good webpage to further automate identification of SQLi returned data")
    parser.add_argument("-k","--knownGood",dest="knownGood",default=None,help="Known good webpage to compare to")
    parser.add_argument("-e","--cookie",dest="cookie",default = None, help = "Cookie of current session to use while replaying the attack")
    parser.add_argument("-l","--logFormat",dest="logFormat",default = None, help = "LogFormat directive from apache configuration")

    options = parser.parse_args()

    mainErrorMsg = checkArgs(options.inLog,
                             options.dbFile,
                             options.website,
                             options.compareToGood,
                             options.knownGood,
                             options.logFormat)
    if mainErrorMsg:
        print mainErrorMsg
        parser.print_help()
        sys.exit(-1)
    else:
        options.logFormat = options.logFormat.replace("\"","\\\"")
        run(options.inLog,
            options.dbFile,
            options.website,
            options.havijParser,
            options.compareToGood,
            options.knownGood,
            options.cookie,
            options.logFormat)

