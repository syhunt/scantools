require "SyMini.Console"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg

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
    top5                Top 5; OWASP Top 5; Gray Box
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
-emu:[browser name] Browser Emulation Mode (default: msie)
    Available Modes:
    chrome    (or c)    Google Chrome
    edge      (or e)    Microsoft Edge
    firefox   (or ff)   Mozilla Firefox
    msie      (or ie)   Internet Explorer
    opera     (or o)    Opera
    safari    (or s)    Safari
    
-srcdir:[local dir] Sets a Target Code Folder (eg. "C:\www\docs\")

-gr                 Generates a report after scanning
-or                 Opens report after generation
-rout:[filename]    Sets the report output filename and format
                     (default: Report_[session name].html)
    Available Formats: html, pdf, doc, rtf, txt, xml
-rtpl:[name]        Sets the report template (default: Standard)
    Available Templates: Standard, Comparison, Compliance, Complete
    
Other parameters:
-mnl:[n]            Sets the maximum number of links per server (default: 10000)
-mnr:[n]            Sets the maximum number of retries (default: 2)
-mcd:[n]            Sets the maximum crawling depth (default: unlimited)
-tmo:[ms]           Sets the timeout time (default: 8000)
-ver:[v]            Sets the HTTP Version (default: 1.1)
-evids              Enables the IDS Evasion
-evwaf              Enables the WAF Evasion
-nodos              Disables Denial-of-Service tests
-nojs               Disables JavaScript emulation and execution
-auser:[username]   Sets a username for server authentication
-apass:[password]   Sets a password for server authentication
-atype:[type]       Sets the auth type; Basic or Form (default: Basic)

-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list
  ]])
end

function printscanresult(hs)
  if hs.vulnerable == true then
    cs.printred('VULNERABLE!')
	if hs.vulncount == 1 then
	  cs.printred('Found 1 vulnerability')
	else
	  cs.printred('Found '..hs.vulncount..' vulnerabilities')
	end
  else
    if hs.aborted == false then
	  cs.printgreen('SECURE.')
	  cs.printgreen('No vulnerabilities found.')
	else
	  cs.printred('UNDETERMINED.')
	  cs.printred('Scan aborted.')
	end
  end
  
  if hs.warnings ~= '' then
    cs.printred('Warnings: '..hs.warnings)
  end
  
  if hasarg('-gr') == true then
    generatereport(hs.sessionname)
  end
end

function generatereport(sessionname)
  print('Generating report...')
  require "Repmaker"
  local outfilename = symini.info.sessionsdir..'Report_'..sessionname..'.html'
  local repprefs = {
    outfilename = arg('rout',outfilename),
    sessionname = sessionname,
    template = arg('rtpl','Standard')
  }
  if repmaker:genreport(repprefs) == true then
    print('Saved to '..outfilename..'.')
    if hasarg('-or') then
      ctk.file.exec(outfilename)
    end
  else
    cs.printred('There was a problem generating '..outfilename)
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
  hs.onlogmessage = function(s) print(s) end
  hs.onvulnfound = printvulndetails
  hs.onrequestdone = requestdone
  
  -- Set the scanner preferences based on switches provided
  hs.debug = hasarg('-dbg')
  hs:prefs_set('syhunt.dynamic.emulation.mode',arg('emu','msie'))
  hs:prefs_set('syhunt.dynamic.protocol.version','HTTP/'..arg('ver','1.1'))
  hs:prefs_set('syhunt.dynamic.evasion.evadeids',hasarg('-evids'))
  hs:prefs_set('syhunt.dynamic.evasion.evadewaf',hasarg('-evwaf'))
  hs:prefs_set('syhunt.dynamic.checks.dos',not hasarg('-nodos'))
  hs:prefs_set('syhunt.dynamic.emulation.javascript.execution',not hasarg('-nojs'))
  if hasarg('-mcd') then
    local n = tonumber(arg('mcd','1'))
    hs:prefs_set('syhunt.dynamic.crawling.depth.uselimit',true)
    hs:prefs_set('syhunt.dynamic.crawling.depth.maxnumber',n)
  end
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
  
  -- Set the scan target and method
  hs.starturl = arg(1)
  hs.huntmethod = arg('hm','appscan')
  hs.sourcedir = arg('srcdir','')
  
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
 ['-help'] = printhelp,
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or startscan
cmd()