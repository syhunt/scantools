require "SyMini.Console"
ctk = require "Catalunya"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg
pfcondreported = false

print(string.format('SYHUNT BREACH %s %s %s',
  symini.info.version_icydark, string.upper(symini.info.modename),
  symini.info.copyright))

function printhelp()
  cs.printwhite('Type scandark -about for more information.')
  print('________________________________________________________________\n')
  print([[
Usage: scandark <domain name> [optional params]
Examples: 
    scandark mydomain.com
    
-sn:[session name]  (if not used, "[unixtime]" will be assigned)

-hm:[method name]   Hunt Method (if not used, "darkplus" will be assigned)
    Available Methods:
    darkplus        Dark Web Scan Plus (Default; SDK+)
    darknosub       Dark Web Scan Plus - No SubDomains (Default; SDK+n)
    dark            Dark Web Scan (SDK)
    darkndeep       Dark'N'Deep Web Scan (DK)
    deep            Deep Web Scan (SD)
    surface         Surface Web Scan (S)
    deeponly        Deep-Only (D)
    darkonly        Dark-Only (K)
    darknoid        Dark Web Scan Paranoid (Experimental; SDK++)
                         
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
    Available Templates: Standard, Complete
-xout:[filename]    Sets the export output filename and format 
    Default: Export_[session name].xml
-xout2:[filename]   Sets a second export output filename and format 
    Default: Export_[session name].xml    
-pfcond:[condition] Sets a pass/fail condition to be reported
-tml:[time]         Sets the maximum scan time limit (default: no limit)
    Examples: 1d, 3h, 2h30m, 50m
-nv                 Turn off verbose. Error and basic info still gets printed

Other parameters:
-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list

  ]])
end

function reportthreat(v)
  cs.printgreen(string.format('Found: %s',v.checkname))
  cs.printgreen('   Risk: '..v.risk)
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

function printscanresult(hs)
  if hs.vulnstatus == 'Vulnerable' then
	if hs.vulncount == 1 then
	  cs.printred('1 alert')
	else
	  cs.printred(hs.vulncount..' alerts')
	end
  end
  if hs.vulnstatus == 'Secure' then  
	  cs.printgreen('SECURE.')
	  cs.printgreen('No alerts.')
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
  i = symini.breach:new()

  if hasarg('-nv') == false then
    i.onlogmessage = function(s) print(s) end
    i.onthreatfound = reportthreat
  end
  
  i:start()
  -- Set the scanner preferences based on switches provided
  i.debug = hasarg('-dbg')
  i.sessionname = arg('sn',symini.getsessionname())
  i.huntmethod = arg('hm','darkplus')
  
  if hasarg('-tml') then
    local n = arg('tml','')
    i:prefs_set('syhunt.icydark.options.timelimit.enabled',true)
    i:prefs_set('syhunt.icydark.options.timelimit.value',n)
  end
  
  -- Expecting a target like: syhunt.com

  local target = arg(1)
  i:scandomain(target)
  print('Done.')
  printscanresult(i)
  i:release()
end

local cmd = {
 ['-about'] = function() print(symini.info.about) end,
 ['-help'] = printhelp,
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or startscan
cmd()