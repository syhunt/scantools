require "SyMini"
ctk = require "Catalunya"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg
pfcondreported = false

print(string.format('SYHUNT CODESCAN %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))

function printhelp()
  cs.printwhite('Type scancode -about for more information.')
  print('________________________________________________________________\n')
  print([[
Usage: scancode <target dir, file or url> [optional params]
Examples: 
    scancode /home/user/mysource/
    scancode c:\source\www\
    scancode c:\source\www\file.php
    scancode c:\mobile\myapp.apk
    scancode "c:\source code\www\"
    scancode git://sub.domain.com/repo.git
    scancode https://github.com/user/repo.git
    scancode https://dev.azure.com/user/project
    scancode https://myserver/tfs/project
    scancode collection:https://dev.azure.com/user$/project
    
-sn:[session name]  (if not used, "[unixtime]" will be assigned)
-hm:[method name]   Hunt Method (if not used "appscan" will be assigned)
    Available Methods:
    appscan             Standard Scan (Client and Server-Side Focused)
    appscanss           Server-Side Code Focused Scan
    top25cwe            CWE Top 25 Most Dangerous Software Errors
    top10               OWASP Top 10
    top5php             OWASP Top 5 PHP
    faultinj            Fault Injection
    fileinc             File Inclusion
    sqlinj              SQL & NoSQL Injection
    xss                 Cross-Site Scripting
    log4shell           Log4Shell Scan    
    spring4shell		Spring4Shell Scan
    malscan             Malware Content
    unvredir            Unvalidated Redirects
    complete            Complete Scan
    comppnoid           Complete Scan, Paranoid

-rb:[branch name]   Sets a GIT repository branch
-tfsv:[version]     Sets a TFS version (default: latest)
    Supported Versions: latest, 2018, 2017, 2015, 2013, 2012, 2010
    Recommended Versions: latest, 2018, 2017, 2015
-nr                 Disables report file generation after scanning
-or                 Opens report after generation
-tk:[trackername]   Sends results to a tracker after scanning.
					Depending on the tracker type, results can be a report,
					export file or vulnerability brief
                    Can be combined with the -pfcond parameter.
					Additional trackers can be provided using -tk2 and -tk3
-rout:[filename]    Sets the report output filename and format
    Default: Report_[session name].html
    Available Formats: html, pdf, json, txt, xml
-rtpl:[name]        Sets the report template (default: Standard)
    Available Templates: Standard, Comparison, Compliance, Complete
-xout:[filename]    Sets the export output filename and format 
    Default: Export_[session name].xml 
-xout2:[filename]   Sets a second export output filename and format
    Default: Export_[session name].xml 
-pfcond:[condition] Sets a pass/fail condition to be reported
-nv                 Turn off verbose. Error and basic info still gets printed
-inc:[mode]         Sets the incremental scan mode (default: targetpref)
    Available Modes: targetpref, auto, forced, disabled
-inctag:[name]      Optionally stores the incremental scan data within a tag
-tml:[time]         Sets the maximum scan time limit (default: no limit)
    Examples: 1d, 3h, 2h30m, 50m

Other parameters:
-excp:[pathlist]    Excludes paths from the analysis (eg: /path/*,/path2/*)
-refurl:[url]       Sets an URL associated with the current source code for
                    reference purposes only
-noifa              Disables input filtering analysis
-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list

  ]])
end

function reportvuln(v)
  cs.printgreen(string.format('Found: %s',v.checkname))
  cs.printgreen('   Risk: '..v.risk)
  if v.params ~= '' then
    cs.printgreen('   Affected Param(s): '..v.params)
  end
  cs.printgreen('   Affected Line(s): '..v.lines)
end

function printscanresult(code)
  if code.vulnstatus == 'Vulnerable' then
    cs.printred('VULNERABLE!')
   	if code.vulncount == 1 then
  		cs.printred('Found 1 vulnerability')
  	else
	  	cs.printred('Found '..code.vulncount..' vulnerabilities')
	  end
	  cs.printred('The following scripts are vulnerable:')
	  cs.printred(code.affectedscripts)
  end
  if code.vulnstatus == 'Secure' then
    if ctk.utils.getarg() ~= '' then
		  cs.printgreen('SECURE.')
	  end
  end
  
  if code.aborted == true then
    cs.printred('Fatal Error.')
    cs.printred(cs.errorreason)
  end   
  if code.warnings ~= '' then
    cs.printred('Warnings: '..code.warnings)
  end  
  
  generateexport(code)
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
  local pfcond = arg('pfcond','')
  submitresults('tk', gen, repprefs)
  submitresults('tk2', gen, repprefs)
  submitresults('tk3', gen, repprefs)  
  -- etrk and si parameters are now deprecated and will be removed in future releases
  -- -tk must be used instead       
  submitresults('si', gen, repprefs)
  submitresults('etrk', gen, repprefs)
end

function startscan()
  print('________________________________________________________________\n')
  local code = symini.code:new()
  code.sessionname = arg('sn',symini.getsessionname())
  code.sessiontag = arg('tag', '')
  
  if hasarg('-nv') == false then
    code.onlogmessage = function(s) print(s) end
    code.onvulnfound = reportvuln   
  end
  
  -- Expecting a target like: scancode c:\source\www\
  local target = arg(1)
  -- Expecting a target between quotes: scancode "c:\source code\www\"
  if ctk.string.beginswith(target,'"') then
    target = ctk.string.after(arg(),'"')
    target = ctk.string.before(target,'"')
  end
  
  if hasarg('-refurl') == true then
    code.targeturl = arg('refurl', '')
  end  
  if hasarg('-excp') == true then
    code.exclusions_pathlist = arg('excp', '')
  end    
  
  -- Set the scanner preferences based on switches provided
  code.huntmethod = arg('hm','normal')
  code.debug = hasarg('-dbg')
  code:prefs_set('syhunt.code.checks.inflt',not hasarg('-noifa'))
  if hasarg('-tml') then
    local n = arg('tml','')
    code:prefs_set('syhunt.code.options.timelimit.enabled',true)
    code:prefs_set('syhunt.code.options.timelimit.value',n)
  end
  code:prefs_update()
  
  -- Set incremental scan mode and tag (if any)
  if hasarg('-inc') then
    code:setincremental({
      mode=arg('inc','targetpref'),
      tag=arg('inctag','')
    })
  end  
  
  if code:isvalidsrcurl(target) then
    code:scanurl({url=target, branch=arg('rb',''), tfsver=arg('tfsv','latest')})
    printscanresult(code)
  elseif ctk.file.exists(target) then
    code:scanfile(target)
    printscanresult(code)
  elseif ctk.dir.exists(target) then
    code:scandir(target)
    printscanresult(code)
  else
    cs.printred(target..' not found or invalid.')
  end
  
  code:release()
end

local cmd = {
 ['-about'] = function() print(symini.info.about) end,
 ['-help'] = printhelp,
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or startscan
cmd()