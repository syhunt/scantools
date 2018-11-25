require "SyMini"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg

print(string.format('SYHUNT CODESCAN %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))

function printhelp()
  cs.printwhite('Type scancode -about for more information.')
  print('________________________________________________________________\n')
  print([[
Usage: scancode [target dir, file or url] [optional params]
Examples: 
    scancode c:\source\www\
    scancode c:\source\www\file.php
    scancode "c:\source code\www\"
    scancode git://sub.domain.com/repo.git
    scancode https://github.com/user/repo.git
    
-sn:[session name]  (if not used, "[unixtime]" will be assigned)
-hm:[method name]   Hunt Method (if not used "normal" will be assigned)
    Available Methods:
    normal              Standard Scan
    top5                Top 5; OWASP Top 5
    faultinj            Fault Injection
    fileinc             File Inclusion
    sqlinj              SQL & NoSQL Injection
    xss                 Cross-Site Scripting
    malscan             Malware Content
    unvredir            Unvalidated Redirects
    complete            Complete Scan
    comppnoid           Complete Scan, Paranoid

-rb                 Sets a repository branch (default: master)
-gr                 Generates a report after scanning
-or                 Opens report after generation
-rout:[filename]    Sets the report output filename and format (default: Report_
[session name].html)
    Available Formats: html, pdf, doc, rtf, txt, xml
-rtpl:[name]        Sets the report template (default: Standard)
    Available Templates: Standard, Comparison, Compliance, Complete
-nv                 Turn off verbose. Error and basic info still gets printed

Other parameters:
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
  if code.vulnerable == true then
    cs.printred('VULNERABLE!')
   	if code.vulncount == 1 then
  		cs.printred('Found 1 vulnerability')
  	else
	  	cs.printred('Found '..code.vulncount..' vulnerabilities')
	  end
	  cs.printred('The following scripts are vulnerable:')
	  cs.printred(code.affectedscripts)
  else
    if ctk.utils.getarg() ~= '' then
		  cs.printgreen('SECURE.')
	  end
  end
  
  if hasarg('-gr') == true then
    generatereport(code.sessionname)
  end
end

function generatereport(sessionname)
  print('Generating report...')
  require "Repmaker"
  local outfilename = symini.info.sessionsdir..'Report_'..sessionname..'.html'
  outfilename = arg('rout',outfilename)
  local repprefs = {
    outfilename = outfilename,
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

function startscan()
  print('________________________________________________________________\n')
  local code = symini.code:new()
  code.sessionname = arg('sn',symini.getsessionname())
  
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
  
  -- Set the scanner preferences based on switches provided
  code.huntmethod = arg('hm','normal')
  code.debug = hasarg('-dbg')
  code:prefs_set('syhunt.code.checks.inflt',not hasarg('-noifa'))
  code:prefs_update()
  
  if code:isvalidsrcurl(target) then
    code:scanurl(target, arg('rb','master'))
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