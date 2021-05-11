require "SyMini"
ctk = require "Catarinka"
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
    malscan             Malware Content
    unvredir            Unvalidated Redirects
    complete            Complete Scan
    comppnoid           Complete Scan, Paranoid

-rb:[branch name]   Sets a repository branch (default: master)
-gr                 Generates a report file after scanning
-gx                 Generates an export file after scanning
-or                 Opens report after generation
-er                 Emails report after generation
-etrk:[trackername] Email preferences to be used when emailing report
-esbj:[subject]     Email subject to be used when emailing report (default:
Syhunt Code Report)
-rout:[filename]    Sets the report output filename and format
    Default: Report_[session name].html
    Available Formats: html, pdf, json, txt, xml
-rtpl:[name]        Sets the report template (default: Standard)
    Available Templates: Standard, Comparison, Compliance, Complete
-xout:[filename]    Sets the export output filename and format 
    Default: Export_[session name].xml 
-xout2:[filename]    Sets a second export output filename and format
    Default: Export_[session name].xml 
-pfcond:[condition] Sets a pass/fail condition to be reported
-nv                 Turn off verbose. Error and basic info still gets printed
-inc:[mode]         Sets the incremental scan mode (default: targetpref)
    Available Modes: targetpref, auto, forced, disabled
-inctag:[name]      Optionally stores the incremental scan data within a tag

Other parameters:
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
  
  if hasarg('-gr') == true then
    generateexport(code.sessionname, 'rout')
  end
  if hasarg('-gx') == true then
    generateexport(code.sessionname, 'xout')
    if hasarg('-xout2') == true then
      generateexport(code.sessionname, 'xout2')    
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
  local isreport = (fnparam == 'rout')  
  local outfilename = symini.info.outputdir..'Report_'..sessionname
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
  local gen = symini.genreport(repprefs)
  if gen.result == true then
    print(gen.resultstr)  
    printpassfailresult(gen)
    if isreport == true then
      handlereport(gen.outfilename)
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
       subject=arg('esbj','Syhunt Code Report')
       })
    end  
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
  
  -- Set the scanner preferences based on switches provided
  code.huntmethod = arg('hm','normal')
  code.debug = hasarg('-dbg')
  code:prefs_set('syhunt.code.checks.inflt',not hasarg('-noifa'))
  code:prefs_update()
  
  -- Set incremental scan mode and tag (if any)
  if hasarg('-inc') then
    code:setincremental({
      mode=arg('inc','targetpref'),
      tag=arg('inctag','')
    })
  end  
  
  if code:isvalidsrcurl(target) then
    code:scanurl({url=target, branch=arg('rb','master')})
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