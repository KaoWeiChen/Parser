#!/usr/bin/env python3

import sys
import requests
import json

from html.parser import HTMLParser

class getMalwareDomain():
    
    def getDataFromWeb(self,page):
        res=requests.get("https://www.malwaredomainlist.com/mdl.php?inactive=&sort=Date&search=&colsearch=All&ascordesc=DESC&quantity=100&page="+str(page))
        return res.text if res.status_code else ""


    def setDataToFile(self,filename,data):
        with open(filename,'w+') as targetfile :
            targetfile.write(str(data))
            targetfile.close()

    def getDataFromFile(self,filename):
        Data =""
        with open(filename,'r') as targetfile :
            for line in targetfile:
                Data += line
        return Data

class MyHTMLParser(HTMLParser):

    start = False
    content =""
    result=[]
    row =[]

    def handle_starttag(self, tag, attrs):
        # attrs[0][1]: #d8d8d8 or #ffffff 
        if tag == 'tr' and len(attrs) == 3 :
            if attrs[0][1] == "#d8d8d8":
                MyHTMLParser.start = True

    def handle_endtag(self, tag):
        # table end tag
        if tag == 'table':
            MyHTMLParser.start = False 
        # html end tag
        elif tag == 'html':
            pass
        elif MyHTMLParser.start == True :
            MyHTMLParser.row.append(MyHTMLParser.content)
            MyHTMLParser.content = ""

    def handle_data(self, data):
        #print "Encountered some data  :", data
        if MyHTMLParser.start == True :
            if data == "\n":
                if len(MyHTMLParser.row) > 0 :
                    MyHTMLParser.result.append(MyHTMLParser.row)
                    MyHTMLParser.row = []
            else:
                MyHTMLParser.content += data

class getJsonList():

    def getJsonList(self,parserresult):
        JsonResult = []
        for i in parserresult:
            for j in i:
                JsonResult.append(self.getJsonFormat(j))
        return JsonResult

    def getJsonFormat(self,data):
        JsonResult = {
            "InfoSource": "MDL",
            "Domain":data[2],
            "IP":data[3].split("/")[0],
            "Description":data[5],
            "FirstFound":data[0],
            "ImpactLevel": 3,
            "TotalHit": 0,
            "DayHit": 0,
            "Exist":data[0],
            "CrossZone": 0,
            "CrossTime": 0,
            "CroseeEvent":0
        }
        return json.dumps(JsonResult)


if __name__ == "__main__":
    WebContentList =[]
    mygetMalwareDomain = getMalwareDomain()
    for page in range(0,1):
        Data = mygetMalwareDomain.getDataFromWeb(page)
        if Data != "":
            WebContentList.append(Data)
        
    getResultList =[] 
    for data in WebContentList:
        parser = MyHTMLParser()
        parser.feed(data)
        getResultList.append(MyHTMLParser.result)
    MySetJsonFile = getJsonList()
    print (MySetJsonFile.getJsonList(getResultList))


