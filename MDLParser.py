#!/usr/bin/python

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import requests
import json

from HTMLParser import HTMLParser


class getMalwareDomain():
	
	def getDataFromWeb(self,page):
		res=requests.get("https://www.malwaredomainlist.com/mdl.php?inactive=&sort=Date&search=&colsearch=All&ascordesc=DESC&quantity=100&page="+str(page))
		return res.text
	
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
	"""
	def __init__(self):
		MyHTMLParser.start = False
		MyHTMLParser.content = ""
		MyHTMLParser.result=[]
		MyHTMLParser.row = []
	"""	
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

class setJsonFile():
	
	def __init__(self,parserresult,resultfilename):
		filecontent =""
		for i in  MyHTMLParser.result :
			filecontent +=  str(self.getDomainJsonFormat(i)) + '\n'
			#filecontent += str(self.getIPJsonFormat(i)) + '\n'
		self.setJsonFile(filecontent,resultfilename)

	def getDomainJsonFormat(self,data):
		JsonResult = {
			"InfoSource": "MDL",
			"Domain":data[2],
			"IP":data[3],
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

	def getIPJsonFormat(self,data):
		
		JsonResult = {
			"InfoSource": "MDL",
			"IP":data[3],
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

	def setJsonFile(self,data,resultfilename):
		with open (resultfilename,'w+') as resultfile:
			resultfile.write(data)
			resultfile.close()


if __name__ == "__main__":
	# get jsonfile from html_source dir
	mygetMalwareDomain = getMalwareDomain()
	for i in range(0,25):
		SoureceFileName = "./html_source/domain_"+ str(i)+".html"
		Data = mygetMalwareDomain.getDataFromFile(SoureceFileName)
		parser = MyHTMLParser()
		parser.feed(Data)
		ResultFileName = "./result/resultJson_" + str(i)
		setJsonFile(MyHTMLParser.result,ResultFileName)
		MyHTMLParser.start = False
                MyHTMLParser.content = ""
                MyHTMLParser.result=[]
                MyHTMLParser.row = []


	# get html content as file
	#mygetMalwareDomain = getMalwareDomain()
	#for i in range(0,25):
	#	Data = mygetMalwareDomain.getDataFromWeb(i)
	#	mygetMalwareDomain.setDataToFile("domain_"+str(i)+".html",Data)

