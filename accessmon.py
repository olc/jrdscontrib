#!/usr/bin/python
# (c) Fabrice Bacchella
#
# Real Time HTTP traffic agent for JRDS
# See: http://jrds.fr/sourcetype/httpxml/accessmonitor
#
#
# Usage:
# The configuration file defines the server parameters, the log location and format,
# and provides some filters which makes possible to select the web applications you want
# to monitor.
# The special application "all" is automatically collecting data for every virtual hosts and urls
# the web server generates logs for.
#
# Let imagine we want to monitor the activity of a web application, which
# has two areas: anonymous and admin. We want to monitor both separately.
#
# Here is an accessmon.ini example:
#
# [server]
# port=8888
# printbad=true
# pidfile=/var/run/accessmon/accessmon.pid
#
# [logfile]
# path=/var/log/apache2/access.log
# column.vhost=0
# column.ip=1
# column.request=5
# column.status=6
# column.timeus=10
#
# [application.myapp_anonymous]
# vhost=www.myapp.*
# negative=/admin/.*
#
# [application.myapp_admin]
# vhost=www.myapp.*
# positive=/admin/.*
#
# Suggestion for the Apache's LogFormat directive:
# LogFormat	"%V %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined_vhost
#
# At JRDS side, add the following probe:
# <probe type="AccessMonitor" label="anonymous">
#    <arg type="Integer" value="8080" />
#    <arg type="String" value="/anonymous" />
# </probe>
# <probe type="AccessMonitor" label="admin">
#    <arg type="Integer" value="8081" />
#    <arg type="String" value="/admin" />
# </probe>
#
# Remark: the heading slash in front of the application name in the probe declaration
# (ie: /anonymous) is NOT a typo. It is needed because it relies on an xml over http
# generic probe which send the string value as a GET parameter.
#
# Run the monitor on the server:
# :; su - www-data -c '/usr/local/bin/accessmon.py --configfile=/usr/local/etc/accessmon.ini'
# Note that user which runs that daemon must be able to read the server logs
#

import time, os
import sys
import re
import socket
import fileinput
import optparse
import resource
import ConfigParser
import fnmatch
import syslog
import glob
import signal

import xml.dom.minidom
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

import threading

class ApplicationFilter:
    vhost = None
    positive = None
    negative = None
    nextone = False
    name = None
    
    def __init__(self, vhost, positive, negative, nextone, name):
        if vhost:
            self.vhost = vhost
        if positive:
            self.positive = re.compile(positive)
        if negative:
            self.negative = re.compile(negative)
        self.nextone = nextone
        self.name = name

    def match(self, vhost, query):
        matched = False
        if self.vhost and fnmatch.fnmatch(vhost, self.vhost):
            matched = True
        if matched and self.positive and self.positive.search(query):
            matched = True
        else:
            matched = False
        if positive and self.negative and self.negative.search(query):
            matched = False
        return matched
        
    def doNext(self):
        return self.nextone
    
class Statistics:
    statusmap = {}
    blmap = {}
    svctime = False
    badLine = 0
    goodLine = 0
    
    startime = time.time()
    
    def __init__(self):
        self.statusmap = {}
        self.blmap = {}
        self.svctime = {}
            
    def valueNode(self, doc, name, value, attributes):
        vnode = doc.createElement(name)
        if value:
            valuetext = doc.createTextNode("%d" % value)
            vnode.appendChild(valuetext)
        for attr in attributes:
            vnode.setAttribute(attr, attributes.get(attr))
        return vnode

    def dump(self): 
        doc = xml.dom.minidom.Document()

        statsNode = doc.createElement("stats")
        uptime = "%d" % ( time.time() - self.startime)
        statsNode.setAttribute("uptime", uptime)
        doc.appendChild(statsNode)

        statsLock.acquire()
        
        statusListNode = doc.createElement("status")
        statsNode.appendChild(statusListNode)
        for statusval in self.statusmap:
            serviceTime = "%f" % self.svctime.get(statusval,0)
            statusCount = "%s" % self.statusmap.get(statusval,0)
            codeNode = self.valueNode(doc, "code", False, {'name': statusval, 'service_time': serviceTime, 'count': statusCount})
            statusListNode.appendChild(codeNode)

        blListNode = doc.createElement("rbl")
        statsNode.appendChild(blListNode)
        for blName in self.blmap:
            blNode = self.valueNode(doc, "bl", self.blmap[blName], {"name": blName})
            #blNode =  doc.createElement("bl")
            #blNode.setAttribute("name", blName)
            #blNode.appendChild(doc.createTextNode("%d" % self.blmap[blName]))
            blListNode.appendChild(blNode)

        goodLineNode = self.valueNode(doc, "goodLine", False, {'count': "%d" % self.goodLine})
        statsNode.appendChild(goodLineNode)

        badLineNode = self.valueNode(doc, "badLine", False, {'count': "%d" % self.badLine})
        statsNode.appendChild(badLineNode)

        statsLock.release()
        return doc.toprettyxml()

class AccessMonHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            applicationName =  self.path[1:]
            if applicationName == '_default':
                syslog.syslog(syslog.LOG_INFO, 'ApplicationName _default is deprecated: use all instead')
                applicationName = 'all'
            if applicationName in allstats:
                self.send_response(200, 'OK')
                self.send_header('Content-type', 'application/xml; charset=utf-8')
                self.send_header('Connection', 'close')
                self.end_headers()
                statistics = allstats[applicationName]
                self.wfile.write( statistics.dump() )
            else:
                self.send_response(404, 'Application unknown')
        except Exception, e:
            syslog.syslog(syslog.LOG_ERR, "failure serving HTTP request" % e )

    def log_request(code=200, size=0):
        pass
        
class Tail:
    statInfo = {}
    fileHandle = {}
    where = {}
    
    def __init__(self, fileglobs, seek=True):
        for fileglob in fileglobs.split(','):
            for filename in glob.glob(fileglob):
                self.config(filename, seek)
     
    def config(self, filename, seek):
        self.statInfo[filename] = os.stat(filename)
        fh = open(filename,'r')
        self.fileHandle[filename] = fh
        #Find the size of the file and move to the end
        if seek:
            self.fileHandle[filename].seek(self.statInfo[filename].st_size)
        self.where[filename] = fh.tell()
       
    def checkRotated(self, filename):
        newStatInfo = os.stat(filename)
        oldStatInfo = self.statInfo[filename]
        self.statInfo[filename] = newStatInfo
        if newStatInfo.st_ino != oldStatInfo.st_ino:
            return True
        if newStatInfo.st_size < oldStatInfo.st_size:
            return True
        return False    
    
    def next(self):
        foundLine = False
        for filename in self.fileHandle.keys():
            fh = self.fileHandle[filename]
            fh.seek(self.where[filename])
            line = fh.readline()
            if line:
                self.where[filename] = fh.tell()
                return line
            else:
            #If file rotated, reconfigure
                if self.checkRotated(filename):
                    syslog.syslog(syslog.LOG_INFO, "rotation detected for %s" % filename)
                    self.config(filename, False)
        if not foundLine:
            time.sleep(1)


def parseline(logline, formatline=False):
    elements = []
    lineiter = lineparser.finditer(logline)
    try:
        while 1:
            found = lineiter.next()
            if found.group(7):
                var = found.group(7)
            elif found.group(3):
                var = found.group(3)
            elif found.group(6):
                var = found.group(6)
            var = var.strip()
            
            if formatline:
                found = formatparser.search(var)
                if found:
                    (key, align, modifier) = ('','','')
                    if found.group(4):
                        key = found.group(4)
                    if found.group(3):
                        align = found.group(3)
                    if found.group(2):
                        modifier = found.group(2)
                    var = "%%{%s}%s%s" % (modifier, align, key)
                    elements.append(var)
            else:
                elements.append(var)
    except StopIteration:
        pass

    return elements
    
def doStats(applistats, status, svctime, badLine):
    statsLock.acquire()
    if badLine:
        applistats.badLine += 1
    else:
        if status:
            applistats.statusmap[status] = applistats.statusmap.get(status, 0) + 1
        if svctime:
            applistats.svctime[status] = applistats.svctime.get(status, 0) + svctime
        applistats.goodLine += 1
    statsLock.release()
        
def foreverParse(rewind, printBad, logfilepattern, columns):
    statuscode = re.compile(r'^([0-9])([0-9])([0-9])$')
    formatparser = re.compile(r'["\[]?%({([^}]+)})?(<|>)?(.)["\]]?')
    queryparser = re.compile('^[A-Z]+ ([^ ]*)( HTTP/)?')
    taillog = False
    while not taillog:
        try:
            taillog = Tail(logfilepattern, not rewind)
        except:
            exctype, value = sys.exc_info()[:2]
            syslog.syslog(syslog.LOG_WARNING, "error with logfile %s: %s" % (logfilepattern, value))
            time.sleep(1)
            continue
            
    #Don't try forever, trynext is a watchdog
    trynext = 0
    while trynext < 5:
        trynext +=1
        try:
            logline = taillog.next()
        except (KeyboardInterrupt, SystemExit):
            keepRunning = False
            break
        except:
            exctype, value = sys.exc_info()[:2]
            syslog.syslog(syslog.LOG_ERR, "tailing file failed: %s" % value)
            time.sleep(1)
            continue

        #Watchdog reset
        trynext = 0
            
        if not logline:
            continue

        loginfos = parseline(logline)
        badLine = False

        #analyze log line only if there is enough column
        if len(loginfos) <= columns['lastcolumn']:
            doStats(allstats.get('all'), False, False, True)
        else:
            status = loginfos[columns.get('status')]
            if not statuscode.search(status):
                badLine = True
                
            svctime = False
            try:
                if 'times' in columns:
                    svctime = int(loginfos[columns.get('times')])
                elif 'timems' in columns:
                    svctime = int(loginfos[columns.get('timems')]) / 1E3
                elif 'timeus' in columns:
                    svctime = int(loginfos[columns.get('timeus')]) / 1E6
            except:
                badLine = True


            #First try to identify the application
            vhost = loginfos[columns.get('vhost')].split(':')[0]
            querymatcher = queryparser.search(loginfos[columns.get('request')])
            if querymatcher:
                query = querymatcher.group(1)
                for appli in applications:
                    if appli.match(vhost, query):
                        applistats = allstats.get(appli.name)
                        doStats(applistats, status, svctime, badLine)
                        if not appli.doNext():
                            break
            else:
                badLine = True
            
            doStats(allstats.get('all'), status, svctime, badLine)
            
        if badLine and printBad:
            syslog.syslog(syslog.LOG_NOTICE, "Bad line: %s" % logline )
    if trynext > 5:
        syslog.syslog(syslog.LOG_ERR, "too much failure, failed")

def createDaemon():
    # do the UNIX double-fork magic, see Stevens' "Advanced
    # Programming in the UNIX Environment" for details (ISBN 0201563177)
    # http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
    try:
       # Fork a child process so the parent can exit. 
       pid = os.fork()
    except OSError, e:
       raise Exception, "%s [%d]" % (e.strerror, e.errno)

    if (pid == 0):	# The first child.
       os.setsid()

       # Is ignoring SIGHUP necessary?
       #
       # It's often suggested that the SIGHUP signal should be ignored before
       # the second fork to avoid premature termination of the process.  The
       # reason is that when the first child terminates, all processes, e.g.
       # the second child, in the orphaned group will be sent a SIGHUP.
       #
       # "However, as part of the session management system, there are exactly
       # two cases where SIGHUP is sent on the death of a process:
       #
       #   1) When the process that dies is the session leader of a session that
       #      is attached to a terminal device, SIGHUP is sent to all processes
       #      in the foreground process group of that terminal device.
       #   2) When the death of a process causes a process group to become
       #      orphaned, and one or more processes in the orphaned group are
       #      stopped, then SIGHUP and SIGCONT are sent to all members of the
       #      orphaned group." [2]
       #
       # The first case can be ignored since the child is guaranteed not to have
       # a controlling terminal.  The second case isn't so easy to dismiss.
       # The process group is orphaned when the first child terminates and
       # POSIX.1 requires that every STOPPED process in an orphaned process
       # group be sent a SIGHUP signal followed by a SIGCONT signal.  Since the
       # second child is not STOPPED though, we can safely forego ignoring the
       # SIGHUP signal.  In any case, there are no ill-effects if it is ignored.
       #
       # import signal           # Set handlers for asynchronous events.
       # signal.signal(signal.SIGHUP, signal.SIG_IGN)

       try:
          pid = os.fork()	# Fork a second child.
       except OSError, e:
          raise Exception, "%s [%d]" % (e.strerror, e.errno)

       if (pid == 0):	# The second child.
          os.chdir('/')
          os.umask(0)
       else:
          os._exit(0)
    else:
        os._exit(0)

    # Default maximum for the number of available file descriptors.
    MAXFD = 1024
    
    # Close all open file descriptors.
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if (maxfd == resource.RLIM_INFINITY):
       maxfd = MAXFD

    # Iterate through and close all file descriptors.
    for fd in range(0, maxfd):
       try:
          os.close(fd)
       except OSError:	# ERROR, fd wasn't open to begin with (ignored)
          pass

    # Redirect the standard I/O file descriptors to the specified file.  Since
    # the daemon has no controlling terminal, most daemons redirect stdin,
    # stdout, and stderr to /dev/null.  This is done to prevent side-effects
    # from reads and writes to the standard I/O file descriptors.

    # The standard I/O file descriptors are redirected to /dev/null by default.
    if (hasattr(os, "devnull")):
       REDIRECT_TO = os.devnull
       # This call to open is guaranteed to return the lowest file descriptor,
       # which will be 0 (stdin), since it was closed above.
       os.open(REDIRECT_TO, os.O_RDWR)	# standard input (0)
       # Duplicate standard input to standard output and standard error.
       os.dup2(0, 1)			# standard output (1)
       os.dup2(0, 2)			# standard error (2)

    return(0)

def handler(signum, frame):
    raise SystemExit, 0

lineparser = re.compile(r'(("((\\"|[^"])+)")|(\[([^\]]+)\])|((, |[^ ])+)) *')

statsLock = threading.Lock()
allstats = { 'all': Statistics()}
filename = 'access_log'
port = 8080
printBad = False
pidfile = False

parser = optparse.OptionParser()
parser.add_option("-f", "--foreground", dest="daemonize", help="Stay in foreground", default=True, action="store_false")
parser.add_option("-r", "--rewind", dest="rewind", help="Rewind from the beginning of file", default=False, action="store_true")
parser.add_option("-#", "--printbad", dest="printBad", help="Print bad line", default=False, action="store_true")
parser.add_option("-p", "--port", dest="port", help="Listen port", type="int")
parser.add_option("-c", "--configfile", dest="configFile", help="Config file", default="accessmon.ini")
parser.add_option("-P", "--pidfile", dest="pidFile", help="pid file", default=False)

(options, args) = parser.parse_args()

if len(args) > 0:
    filename = args[0]

applications = []

columns = { 'ip': 1, 'vhost':2, 'request':3, 'status': 5, 'lastcolumn': 5}

reApplicationSection = re.compile(r'application\.(.*)')
reColumn = re.compile('column\.(.*)')

config = ConfigParser.SafeConfigParser()
config.read(options.configFile)

for section in config.sections():    
    if section == 'server':
        if config.has_option(section, "port"):
            port = int(config.get(section, "port"))
        if config.has_option(section, "printbad"):
            printBad = True
        if config.has_option(section, "pidfile"):
            pidFile = config.get(section, "pidfile")
        
    elif section == 'logfile':
        for optionName in config.options(section):
            if optionName == "path":
                filename = config.get(section, "path")
            columnFound = reColumn.search(optionName)
            if columnFound:
                columnName = columnFound.group(1)
                columns[columnName] = int(config.get(section, optionName))
                columns['lastcolumn'] = max(columns[columnName], columns['lastcolumn'])
            
    else:
        found =  reApplicationSection.search(section)
        if found:
            donext = False
            applicationName = found.group(1)
            if config.has_option(section, "vhost"):
                vhost = config.get(section, "vhost")
            else:
                vhost = None
            if config.has_option(section, "positive"):
                positive = config.get(section, "positive")
            else:
                positive = None
            if config.has_option(section, "negative"):
                negative = config.get(section, "negative")
            else:
                negative = None
            if config.has_option(section, "continue"):
                donext = config.getboolean(section, "continue")
#            applications[applicationName] = ApplicationFilter(vhost, positive, negative, donext)
            applications.append(ApplicationFilter(vhost, positive, negative, donext, applicationName))
            allstats[applicationName] = Statistics()

if options.port:
    port = options.port
if options.printBad:
    printBad = options.printBad
if options.pidFile:
    pidFile = options.pidFile

syslog.openlog("accessmon", 0, syslog.LOG_DAEMON)
if options.daemonize:
    try:
        createDaemon()
    except :
        exctype, value = sys.exc_info()[:2]
        syslog.syslog(syslog.LOG_ERR, "Access monitor daemon failed to start: %s" % value)

if pidFile:
    pid = os.getpid()
    try:
        file(pidFile,'w+').write("%s\n" % pid)
    except Exception, e:
        syslog.syslog(syslog.LOG_ERR, "Access monitor daemon failed to write pid file: %s" % e)
        sys.exit(1)
    signal.signal(signal.SIGTERM, handler)
    
syslog.syslog(syslog.LOG_WARNING, "Access monitor daemon started")

try:
    webserver = HTTPServer(('', port), AccessMonHandler)
    webServerThread = threading.Thread(None, webserver.serve_forever, 'webServer', () , {})
    webServerThread.setDaemon(True)
    webServerThread.start()      
except Exception, e:
    syslog.syslog(syslog.LOG_ERR, "Access monitor daemon failed to start http server: %s" % e)
else:
    try:
        foreverParse(options.rewind, printBad, filename, columns)
    except SystemExit,KeyboardInterrupt:
        True
syslog.syslog(syslog.LOG_WARNING, "Access monitor daemon stopped")
syslog.closelog()
if pidFile:
    os.remove(pidFile)
