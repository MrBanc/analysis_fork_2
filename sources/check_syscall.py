import csv
from collections import defaultdict

COVERAGE_SUITE="-coverage-suite/"
COVERAGE_BENCHMARK="-coverage-benchmark/"

def addSyscalls(syscallName, covFolder, used):
    covFolder.allSyscalls.add(syscallName)
    if used:
        covFolder.covSyscalls.add(syscallName)
    else:
        covFolder.notCovSyscalls.add(syscallName)
        covFolder.manualSetSyscalls.add(syscallName)
            
def readCsvManual(covFolder):
    
    if COVERAGE_SUITE in covFolder.htmlFolder:
        colIndex = 2
    else:
        colIndex = 1
        
    csvReader = csv.reader(open(covFolder.csvFile, 'r'), delimiter=',')
    for row in csvReader:
        syscallName = row[0]
        syscallUsed = row[colIndex].upper().strip()
        addSyscalls(syscallName, covFolder, syscallUsed == "X")
    