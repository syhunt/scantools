require "SyMini.Console"
ctk = require "Catalunya"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg
pfcondreported = false

print(string.format('SYHUNT URLSCAN %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))

function printhelp()
  cs.printwhite('Type scanurl -about for more information.')
  print('________________________________________________________________\n')
  print([[
Usage: scanurl <starturl> [optional params]
Examples: 
    scanurl http://www.somehost.com/
    scanurl http://www.somehost.com/ -mnl:100 -nodos
    
-sn:[session name]  (if not used, "[unixtime]" will be assigned)
-hm:[method name]   Hunt Method (if not used, "appscan" will be assigned)
    Available Methods:
    appscan   (or as)   Web Application Scan (Client and Server-Side Focused); Gray Box
    appscanss (or asss) Web Application Scan (Server-Side Focused); Gray Box
    structbf  (or sbf)  Web Structure Brute Force; Black Box
    top25cwe  (or t25)  CWE Top 25 Most Dangerous Software Errors; Gray Box
    top10     (or t10)  OWASP Top 10; Gray Box
    top5php   (or t5)   OWASP Top 5 PHP; Gray Box
    faultinj  (or fi)   Fault Injection; Gray Box
    sqlinj    (or sqli) SQL & NoSQL Injection; Gray Box
    xss                 Cross-Site Scripting; Gray Box
    fileinc   (or finc) File Inclusion; Gray Box
    fileold   (or fold) Old & Backup Files; Gray Box
    log4shell (or l4s)  Log4Shell Scan; Gray Box
    spring4shell (or s4s)  Spring4Shell Scan; Gray Box
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
    
-srcdir:[local dir] Sets a Target Code Folder (eg. "C:\www\docs\" or "/home/user/www/")

-tk:[trackername]   Sends results to a tracker after scanning.
					Depending on the tracker type, results can be a report,
					export file or vulnerability brief
                    Can be combined with the -pfcond parameter.
					Additional trackers can be provided using -tk2 and -tk3
-nr                 Disables report file generation after scanning
-or                 Opens report after generation
-rout:[filename]    Sets the report output filename and format
    Default: Report_[session name].html
    Available Formats: html, pdf, json, txt, xml
-rtpl:[name]        Sets the report template (default: Standard)
    Available Templates: Standard, Comparison, Compliance, Complete
-xout:[filename]    Sets the export output filename and format 
-xout2:[filename]   Sets a second export output filename and format 
-pfcond:[condition] Sets a pass/fail condition to be reported
-nv                 Turn off verbose. Error and basic info still gets printed
-inc:[mode]         Sets the incremental scan mode (default: targetpref)
    Available Modes: targetpref, auto, forced, disabled
-inctag:[name]      Optionally stores the incremental scan data within a tag
    
Other parameters:
-mnl:[n]            Sets the maximum number of links per server (default: 10000)
-mnr:[n]            Sets the maximum number of HTTP request retries (default: 2)
-tmo:[ms]           Sets the HTTP request timeout time (default: 8000)
-tml:[time]         Sets the maximum scan time limit (default: no limit)
    Examples: 1d, 3h, 2h30m, 50m
-ver:[v]            Sets the HTTP Version (default: 1.1)
-evids              Enables the IDS Evasion
-evwaf              Enables the WAF Evasion
-nofris             Disables auto follow off-domain redirect in Start URL
-nodos              Disables Denial-of-Service tests
-nojs               Disables JavaScript emulation and execution
-auser:[username]   Sets a username for server authentication
-apass:[password]   Sets a password for server authentication
-atype:[type]       Sets the auth type; Basic, Bearer, Digest, Form and Manual

-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list
  ]])
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
  generateexport(hs)
end

function submitresults(argname, gen, repprefs)
  if hasarg('-'..argname) == true then
   local notifytracker = true
   local hs = symini.hybrid:new()
   hs:start()
   gen.trackername = arg(argname,'')
   local notifyonfailonly = hs:tracker_getvalue(gen.trackername, 'notifyonfailonly')
   if notifyonfailonly == true and gen.passfail_result == true and hasarg('-pfcond') == true then
     notifytracker = false
   end
   if notifytracker == true then     
     local issue = hs:tracker_getissuetemplate(gen)  
     issue.debug = hasarg('-dbg')
    -- Ignore if a compatible report or export file for the specified tracker is
    -- available. If not, generate compatible one
     repprefs.skipfirst = true
     repprefs.overwrite = false
     repprefs.outfilename = nil
     repprefs.outfilename2 = issue.attachfilename
     print('Attachment read from: '..issue.attachfilename_source)
     local gen = symini.genreport(repprefs)
     -- Updates the attachment files (if any)
     issue.attachfilename = gen.outfilename2
     -- Finally, submits the results to the tracker
     local res = hs:tracker_sendissue(issue) 
       if res.success == true then
         cs.printgreen('Scan results sent! '..res.errormsg)
       else
         cs.printred('Failed to send scan results! '..res.errormsg)
       end
      if issue.debug == true then
       print(res.debuglog)
     end
   end
   hs:release()
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
function generateexport(hs)
  if hasarg('-nr') == false then
    print('Generating report...')
  end
  local repprefs = {
    outfilename  =  arg('rout',''),
    outfilename2 =  arg('xout',''),
    outfilename3 =  arg('xout2',''),  
    sessionname = hs.sessionname,
    template = arg('rtpl','Standard'),
    passfailcond = arg('pfcond',''),
    skipfirst = hasarg('-nr'),
    open = hasarg('-or')
  }
  local gen = symini.genreport(repprefs)
  if hasarg('-nr') == false then
    if gen.result == true then
      print(gen.resultstr)  
      printpassfailresult(gen)
    else
      cs.printred(gen.resultstr)
    end
  end
  -- Submits results to the trackers (if any) if the pass/fail condition is met
  submitresults('tk', gen, repprefs)
  submitresults('tk2', gen, repprefs)
  submitresults('tk3', gen, repprefs) 
  -- etrk and si parameters are now deprecated and will be removed in future releases
  -- -tk must be used instead       
  submitresults('si', gen, repprefs)
  submitresults('etrk', gen, repprefs)
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
  hs.sessiontag = arg('tag', '')
  
  if hasarg('-nv') == false then
    hs.onlogmessage = function(s) print(s) end
    hs.onvulnfound = printvulndetails
    hs.onrequestdone = requestdone
  end
  
  -- Set the scanner preferences based on switches provided
  hs.debug = hasarg('-dbg')
  hs:start()
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
  if hasarg('-tml') then
    local n = arg('tml','')
    hs:prefs_set('syhunt.dynamic.options.timelimit.enabled',true)
    hs:prefs_set('syhunt.dynamic.options.timelimit.value',n)
  end
  
  -- Set the scan target
  if hasarg('-nofris') then
    hs.starturl_folre = false
  end
  hs.starturl = arg(1)
  hs.huntmethod = arg('hm','appscan')
  hs.sourcedir = arg('srcdir','')
  
  -- Set auth credentials (if any)
  if hasarg('-atype') then
    hs:setauth({
     username=arg('auser',''),
     password=arg('apass',''),
     authtype=arg('atype','Basic')
    })
  end
  
  -- Set incremental scan mode and tag (if any)
  if hasarg('-inc') then
    hs:setincremental({
      mode=arg('inc','targetpref'),
      tag=arg('inctag','')
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