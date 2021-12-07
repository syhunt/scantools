require "SyMini.Console"
ctk = require "Catalunya"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg
pfcondreported = false

print(string.format('SYHUNT ICYDARK %s %s %s',
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
                         
-gr                 Generates a report file after scanning
-gx                 Generates an export file after scanning
-or                 Opens report after generation
-er                 Emails report after generation
-etrk:[trackername] Email preferences to be used when emailing report
-esbj:[subject]     Email subject to be used when emailing report (default:
Syhunt IcyDark Report)
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
       subject=arg('esbj','Syhunt IcyDark Report')
       })
    end  
end

function startscan()
  print('________________________________________________________________\n')
  i = symini.icydark:new()

  if hasarg('-nv') == false then
    i.onlogmessage = function(s) print(s) end
    i.onthreatfound = reportthreat
  end
  
  i:start()
  -- Set the scanner preferences based on switches provided
  i.debug = hasarg('-dbg')
  i.sessionname = arg('sn',symini.getsessionname())
  i.huntmethod = arg('hm','darkplus')
  
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