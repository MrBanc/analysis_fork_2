import os
import re

import argparse
from bs4 import BeautifulSoup
from check_syscall import readCsvManual, COVERAGE_SUITE, COVERAGE_BENCHMARK
from classes import *
from output_html import *
from process_call import buildCallee, createGraph, buildCaller
from utility import *
from pathlib import Path

verbose = False

WORKDIR         = "/home/gain/analysis/apps/"
APP             = "haproxy"
TYPE_TEST       = COVERAGE_BENCHMARK
AGGREGATE_FILE  = "log_aggregated"

LINECOV         = "lineCov"
LINENOCOV       = "lineNoCov"

#
# Quick and Dirty parsing (since we have only line as html):
#
def search_function(line, cv):
    c_keyworks = ["if", "while", "switch", "for"]
    regex = r"(\w+)\s*\("
    matches = re.findall(regex, line)

    if len(matches) == 0:
        # No functions, no keywords
        return None
    elif len(matches) == 1:
        # Maybe either a function or a keywork
        if matches[0].replace(" ", "") in c_keyworks:
            # It is only a keyword so return
            print_verbose("[" + cv +"] Ignore: [" + matches[0].replace(" ", "") + "]\n-------", verbose)
            return None
        
        print_verbose("[" + cv +"] Take:   [" + matches[0].replace(" ", "") + "]\n-------", verbose)

        htmlLine = HtmlLine(line)
        htmlLine.fctList.append(matches[0].replace(" ", ""))
        return htmlLine
    elif len(matches) > 1:
        # Contains several possibilities (functions, keywords, ...)
        htmlLine = HtmlLine(line)
        for m in matches:
            m = m.replace(" ", "")
            if m in c_keyworks:
                print_verbose("[" + cv +"] Ignore: [" + m + "]", verbose)
            else:
                print_verbose("[" + cv +"] Take:   [" + m + "]\n-------", verbose)
                htmlLine.fctList.append(m)
        return htmlLine

def getHtmlLines(filename, covFolder):
    htmlFile = HtmlFile(filename)
    with open(htmlFile.filename, "r", encoding='utf-8') as f:
        text= f.read()
        htmlContent = BeautifulSoup(text, 'html.parser')

        for span in htmlContent.find_all("span", {"class": LINECOV}):
            htmlLine = search_function(span.get_text(), LINECOV)
            
            if htmlLine:
                htmlFile.linesCov.append(htmlLine)
                for fct in htmlLine.fctList:
                    if fct in syscall_list:
                        covFolder.allSyscalls.add(fct)
                        covFolder.covSyscalls.add(fct)
                    try:
                        covFolder.covFct[fct].add(filename + "#" + str(span.parent['name']))
                    except:
                        covFolder.covFct[fct].add(filename)             

        for span in htmlContent.find_all("span", {"class": LINENOCOV}):
            htmlLine = search_function(span.get_text(), LINENOCOV)
            if htmlLine:
                htmlFile.linesNotCov.append(htmlLine)
                for fct in htmlLine.fctList:
                    if fct in syscall_list:
                        # This contains temporary not covered syscalls since these ones may be covered later (filter done after)
                        covFolder.allSyscalls.add(fct)
                        covFolder.notCovSyscalls.add(fct)
                    try:
                        covFolder.notCovFct[fct].add(filename + "#" + str(span.parent['name']))
                    except:
                        covFolder.notCovFct[fct].add(filename)
    
    covFolder.mapHtmlFile[filename] = htmlFile

def iterateHtmlFolder(covFolder):

    pathlist = Path(covFolder.htmlFolder).glob('**/*.gcov.html')
    for path in pathlist:
        print(path)
        str_path = str(path)
        print_verbose("Gathering info of: " + str(str_path), verbose)
        if not os.path.isfile(str_path) or not os.access(str_path, os.R_OK):
            print_err("ERROR: Can't open html file, \"{}\"!".format(str_path))
            sys.exit(-1)
        getHtmlLines(str_path, covFolder)

def iterateExtandFolder(gObj):

    pathlist = Path(gObj.expandFolder).glob('**/*.expand')
    for path in pathlist:
        
        str_path = str(path)
        print_verbose("Gathering info of: " + str(str_path), verbose)
        if not os.path.isfile(str_path) or not os.access(str_path, os.R_OK):
            print_err("ERROR: Cannot open rtl file, \"{}\"!".format(str_path))
            sys.exit(-1)
        gObj.pathList.append(str_path)

def generateResults(gObj, covFolder, args, resultsFolder):
    isExist = os.path.exists(resultsFolder)
    if not isExist:
        os.makedirs(resultsFolder)

    if args.savehtml:
        print("[INFO] Generating result files (as .html) into: " + resultsFolder)
        saveResultsHtml(resultsFolder, covFolder)
    if args.aggregate:
        outAggregated = os.path.join(resultsFolder, AGGREGATE_FILE + ".html")
        print("[INFO] Generating aggregated html file: " + outAggregated)
        saveAggregateHtml(outAggregated, covFolder)
    if args.unique:
        outAggregated = os.path.join(resultsFolder, AGGREGATE_FILE + "_functions.html")
        print("[INFO] Generating unique aggregated html file: " + outAggregated)
        saveAggregateHtmlUnique(gObj, args.maxdisplay, outAggregated, covFolder, resultsFolder)

def main():
    global verbose

    parser = argparse.ArgumentParser()
    parser.add_argument('--app', help='Path to the application src/ to analyse', default=APP)
    parser.add_argument('--coverage', help='Type of coverafe (default:' + TYPE_TEST + ')', default=TYPE_TEST)
    parser.add_argument('--aggregate', '-a', type=str2bool, nargs='?', const=True, help='Aggregate results into single aggregate file ('+ AGGREGATE_FILE + ')' , default=True)
    parser.add_argument('--savehtml', '-s', type=str2bool, nargs='?', const=True, help='Save intermediate results as .html', default=False)
    parser.add_argument('--unique', type=str2bool, nargs='?', const=True, help='Count only function once in aggregated unique file', default=True)
    parser.add_argument('--maxdisplay', type=int, help='Max referenced files to show in the aggregate unique file (default: 10)', default=10)
    parser.add_argument('--verbose', '-v', type=str2bool, nargs='?', const=True, help='Verbose mode', default=False)

    # Use to manage the call graph
    parser.add_argument('--generatePdf', type=str2bool, nargs='?', const=True, help='Generate PDF files', default=False)
    parser.add_argument('--generateDot', type=str2bool, nargs='?', const=True, help='Generate dot files', default=False)
    parser.add_argument("--exclude", help="RegEx for functions to exclude", type=str, metavar="REGEX")
    parser.add_argument("--no-externs", help="Do not show external functions", action="store_true")
    parser.add_argument("--no-warnings", help="Do not show warnings on the console", action="store_true")
    parser.add_argument("--max-depth", metavar="DEPTH", help="Maximum tree depth traversal, default no depth", type=int, default=0)

    args = parser.parse_args()
    
    if args.coverage != COVERAGE_SUITE or args.coverage != COVERAGE_BENCHMARK:
        print_err("The coverage args must either be " + COVERAGE_SUITE + " or " + COVERAGE_BENCHMARK)
     
    appName = args.app
    if "/" in args.app:
        appName = args.app.split("/")[-1]
    
    htmlFolder     = os.path.join(args.app, appName + args.coverage)
    expandFolder   = os.path.join(args.app, appName + "_expand/")
    csvFile        = os.path.join(args.app, appName + ".csv")
    resultsFolder  = os.path.join(args.app, "results" + args.coverage)
    
    verbose = args.verbose

    # Read the coverage
    covFolder = CovFolder(appName, htmlFolder, resultsFolder, csvFile)
    print("[INFO] Analysing html folder: " + htmlFolder + " (this may take some times...)")
    iterateHtmlFolder(covFolder)

    # Build the grap
    gObj = GraphObject(expandFolder, os.path.join(resultsFolder, "dot_files"), os.path.join(resultsFolder, "pdf_files"))
    print("[INFO] Analysing expand folder: " + gObj.expandFolder + " (this may take some times...)")
    iterateExtandFolder(gObj)
    if len(gObj.pathList) == 0:
        print_err("Cannot find .expand files. Exit")
        sys.exit(1)
    print("[INFO] Generating call graph: " + gObj.expandFolder + " (this may take some times...)")
    createGraph(gObj, covFolder, args)
    
    # Manual inspection of the data
    readCsvManual(covFolder)
    
    # Track syscalls as entrypoint to have a plot
    for s in covFolder.allSyscalls:
        buildCallee(gObj, covFolder, [s], args)

    # Generate HTML output
    generateResults(gObj, covFolder, args, resultsFolder)
    
    if verbose:
        print_verbose("Printing aliases functions:", verbose)
        for obj in gObj.aliases:
            print(obj)

if __name__== "__main__":
    main()
