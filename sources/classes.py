from collections import defaultdict

class GraphObject:
    def __init__(self, expandFolder, outDotFolder, outPdfFolder):
        self.expandFolder = expandFolder
        self.pathList = list()
        self.functions = dict()
        self.aliases = set()
        self.outDotFolder = outDotFolder
        self.outPdfFolder = outPdfFolder

class CovFolder:
    def __init__(self, appName, htmlFolder, resultsFolder, csvFile):
        self.appName = appName
        self.htmlFolder = htmlFolder
        self.resultsFolder = resultsFolder
        self.csvFile = csvFile
        self.mapHtmlFile = dict()
        self.covFct = defaultdict(set)
        self.notCovFct = defaultdict(set)
        self.allSyscalls = set()
        self.covSyscalls = set()
        self.manualSetSyscalls = set()
        self.notCovSyscalls = set()
        self.syscallsNeighboursCov = defaultdict(set)
        self.syscallsNeighboursNotCov = defaultdict(set)

class HtmlFile:
    def __init__(self, filename):
        self.filename = filename
        self.name = filename.split("/")[-1]
        self.linesCov = list()
        self.linesNotCov = list()

class HtmlLine:
    def __init__(self, innerText):
        self.innerText = innerText
        self.fctList = list()
