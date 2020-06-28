require "SyMini.Console"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg
pfcondreported = false

print(string.format('SYHUNT URLSCAN %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))

function printhelp()
  cs.printwhite('Type scanurl -about for more information.')
  print('________________________________________________________________\n')
  print([[
Usage: scanurl [starturl] [optional params]
Examples: 
    scanurl http://www.somehost.com/
    scanurl http://www.somehost.com/ -mnl:100 -nodos
    
-sn:[session name]  (if not used, "[unixtime]" will be assigned)
-hm:[method name]   Hunt Method (if not used, "appscan" will be assigned)
    Available Methods:
    appscan   (or as)   Web Application Scan; Gray Box
    structbf  (or sbf)  Web Structure Brute Force; Black Box
    top25cwe  (or t25)  CWE Top 25 Most Dangerous Software Errors; Gray Box
    top10     (or t10)  OWASP Top 10; Gray Box
    top5php   (or t5)   OWASP Top 5 PHP; Gray Box
    faultinj  (or fi)   Fault Injection; Gray Box
    sqlinj    (or sqli) SQL & NoSQL Injection; Gray Box
    xss                 Cross-Site Scripting; Gray Box
    fileinc   (or finc) File Inclusion; Gray Box
    fileold   (or fold) Old & Backup Files; Gray Box
    malscan   (or mal)  Malware Content; Gray Box
    unvredir  (or ur)   Unvalidated Redirects; Gray Box
    passive   (or pas)  Passive Scan; Black box
    spider    (or spd)  Spider Only
    complete  (or cmp)  Complete Scan; Gray Box
    compnodos (or cnd)  Complete Scan, No DoS; Gray Box
    comppnoid (or cpn)  Complete Scan, Paranoid; Gray box
-emu:[browser name] Browser Emulation Mode (default: chrome)
    Available Modes:
    chrome    (or c)    Google Chrome
    edge      (or e)    Microsoft Edge
    firefox   (or ff)   Mozilla Firefox
    msie      (or ie)   Internet Explorer
    opera     (or o)    Opera
    safari    (or s)    Safari
    
-srcdir:[local dir] Sets a Target Code Folder (eg. "C:\www\docs\")

-gr                 Generates a report file after scanning
-gx                 Generates an export file after scanning
-or                 Opens report after generation
-er                 Emails report after generation
-etrk:[trackername] Email preferences to be used when emailing report
-esbj:[subject]     Email subject to be used when emailing report (default:
Syhunt Hybrid Report)
-rout:[filename]    Sets the report output filename and format
    Default: Report_[session name].html
    Available Formats: html, pdf, doc, json, rtf, txt, xml
-rtpl:[name]        Sets the report template (default: Standard)
    Available Templates: Standard, Comparison, Compliance, Complete
-xout:[filename]    Sets the export output filename and format 
    Default: Export_[session name].xml
-xout2:[filename]   Sets a second export output filename and format 
    Default: Export_[session name].xml    
-pfcond:[condition] Sets a pass/fail condition to be reported
-nv                 Turn off verbose. Error and basic info still gets printed
    
Other parameters:
-mnl:[n]            Sets the maximum number of links per server (default: 10000)
-mnr:[n]            Sets the maximum number of retries (default: 2)
-mcd:[n]            Sets the maximum crawling depth (default: unlimited)
-tmo:[ms]           Sets the timeout time (default: 8000)
-ver:[v]            Sets the HTTP Version (default: 1.1)
-evids              Enables the IDS Evasion
-evwaf              Enables the WAF Evasion
-nofris             Disables auto follow off-domain redirect in Start URL
-nodos              Disables Denial-of-Service tests
-nojs               Disables JavaScript emulation and execution
-auser:[username]   Sets a username for server authentication
-apass:[password]   Sets a password for server authentication
-atype:[type]       Sets the auth type; Basic or Form (default: Basic)

-checks             Exports Syhunt Checks list
-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list
  ]])
end

function printchecks()
  local hs = symini.hybrid:new()
  hs.onlogmessage = function(s) print(s) end
  hs:start()
  hs:getchecklist()
  hs:release()
end

function printscanresult(hs)
  if hs.vulnstatus == 'Vulnerable' then
    cs.printred('VULNERABLE!')
	if hs.vulncount == 1 then
	  cs.printred('Found 1 vulnerability')
	else
	  cs.printred('Found '..hs.vulncount..' vulnerabilities')
	end
  end
  if hs.vulnstatus == 'Secure' then  
	  cs.printgreen('SECURE.')
	  cs.printgreen('No vulnerabilities found.')
  end
  if hs.aborted == true then
      cs.printred('Fatal Error.')
	  cs.printred(hs.errorreason)
  end  
  if hs.warnings ~= '' then
     cs.printred('Warnings: '..hs.warnings)
  end
  
  if hasarg('-gr') == true then
    generateexport(hs.sessionname, 'rout')
  end
  if hasarg('-gx') == true then
    generateexport(hs.sessionname, 'xout')
    if hasarg('-xout2') == true then
      generateexport(hs.sessionname, 'xout2')    
    end
  end   
end

function printpassfailresult(g)
  if pfcondreported == false then
   if hasarg('-pfcond') == true then
     pfcondreported = true
     if g.passfail_result == true then
       cs.printgreen('Pass/Fail Status: PASSED.')
     else
       cs.printred('Pass/Fail Status: FAILED.')    
       cs.printred(g.passfail_resultstr)
     end
   end
  end
end

-- Generates a scan report or export file
function generateexport(sessionname, fnparam)
  require "Repmaker"
  local isreport = (fnparam == 'rout')  
  local outfilename = symini.info.sessionsdir..'Report_'..sessionname
  if isreport == true then
    print('Generating report...')
    outfilename = outfilename..'.html'
  else
    print('Generating export...')    
    outfilename = outfilename..'.xml'
  end
  outfilename = arg(fnparam,outfilename) 
  local repprefs = {
    outfilename = outfilename,
    sessionname = sessionname,
    template = arg('rtpl','Standard'),
    passfailcond = arg('pfcond','')
  }
  local gen = repmaker:genreport(repprefs)
  if gen.result == true then
    print(gen.resultstr)  
    printpassfailresult(gen)
    if isreport == true then
      handlereport(outfilename)
    end
  else
    cs.printred(gen.resultstr)
  end
end

-- Opens or emails report to user after being generated
function handlereport(outfilename)
    if hasarg('-or') then
      ctk.file.exec(outfilename)
    end
    if hasarg('-er') then
      symini.emailreport({
       tracker=arg('etrk',''),
       filename=outfilename,
       subject=arg('esbj','Syhunt Hybrid Report')
       })
    end  
end

function printvulndetails(v)
  local loc = v.location
  local ps = function(desc,key)
      if key ~= '' then
        cs.printgreen(string.format('   %s: %s',desc,key))
      end
    end
  if v.locationsrc ~= '' then
    -- Replace by source code location
    loc = v.locationsrc
  end
  cs.printgreen(string.format('Found: %s at %s',v.checkname,loc))
  ps('References (CVE)',v.ref_cve)
  ps('References (CWE)',v.ref_cwe)
  ps('References (OSVDB)',v.ref_osvdb)
  ps('Risk',v.risk)
  ps('Affected Browsers(s)',v.browsers)
  ps('Affected Param(s)',v.params)
  ps('Affected Line(s)',v.lines)
  ps('POST Param(s)',v.postdata)
  ps('Injected Data',v.injecteddata)
  ps('Matched Sig',v.matchedsig)
  ps('Status Code',v.statuscode)
end

function requestdone(r)
  -- Print requests during spidering stage
  if r.isseccheck == false then
    local s = r.method..' '..r.url
    if r.postdata ~= '' then
      s = s..' ['..r.postdata..' ]'
    end
    cs.printgreen(s)
  end
end

function startscan()
  print('________________________________________________________________\n')
  local hs = symini.hybrid:new()
  hs.sessionname = arg('sn',symini.getsessionname())
  
  if hasarg('-nv') == false then
    hs.onlogmessage = function(s) print(s) end
    hs.onvulnfound = printvulndetails
    hs.onrequestdone = requestdone
  end
  
  -- Set the scanner preferences based on switches provided
  hs.debug = hasarg('-dbg')
  hs:prefs_set('syhunt.dynamic.emulation.mode',arg('emu','chrome'))
  hs:prefs_set('syhunt.dynamic.protocol.version','HTTP/'..arg('ver','1.1'))
  hs:prefs_set('syhunt.dynamic.evasion.evadeids',hasarg('-evids'))
  hs:prefs_set('syhunt.dynamic.evasion.evadewaf',hasarg('-evwaf'))
  hs:prefs_set('syhunt.dynamic.checks.dos',not hasarg('-nodos'))
  hs:prefs_set('syhunt.dynamic.emulation.javascript.execution',not hasarg('-nojs'))
  if hasarg('-mnl') then
    local n = tonumber(arg('mnl','10000'))
    hs:prefs_set('syhunt.dynamic.crawling.max.linkspersite',n)
  end
  if hasarg('-mnr') then
    local n = tonumber(arg('mnr','2'))
    hs:prefs_set('syhunt.dynamic.protocol.retries',n)
  end
  if hasarg('-tmo') then
    local n = tonumber(arg('tmo','8000'))
    hs:prefs_set('syhunt.dynamic.protocol.timeout.value',n)
  end
  hs:start()
  
  -- Set the scan target
  if hasarg('-nofris') then
    hs.starturl_folre = false
  end
  hs.starturl = arg(1)
  hs.huntmethod = arg('hm','appscan')
  hs.sourcedir = arg('srcdir','')
  
  -- Set site preferences (if any)
  -- Must be called after setting the start URL
  if hasarg('-mcd') then
    local n = tonumber(arg('mcd','1'))
    siteprefs_set(hs.starturl, 'site.syhunt.dynamic.crawling.limitdepth', true)
    siteprefs_set(hs.starturl, 'site.syhunt.dynamic.crawling.maxdepth', n)
  end  
  
  -- Set auth credentials (if any)
  if hasarg('-auser') then
    hs:setauth({
     username=arg('auser',''),
     password=arg('apass',''),
     authtype=arg('atype','Basic')
    })
  end
  
  -- Start the scan
  hs:scan()
  print('Done.')
  printscanresult(hs)
  hs:release()
end

local cmd = {
 ['-about'] = function() print(symini.info.about) end,
 ['-checks'] = printchecks, 
 ['-help'] = printhelp,
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or startscan
cmd()