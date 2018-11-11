require "SyMini.Console"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg
gdbfn = symini.info.progdir.."\\Packs\\GeoLite2\\GeoLite2-Country.mmdb"
geodb = require "mmdb".open(gdbfn)

print(string.format('SYHUNT INSIGHT %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))

function printhelp()
  cs.printwhite('Type scanlog -about for more information.')
  print('________________________________________________________________\n')
  print([[
Usage: scanlog [logfilename] [optional params]
Examples: 
    scanlog c:\www\logs\access.log
    scanlog "c:\web logs\access.log"
    
-fmt:[format name]  Log Format (if not used, "auto" will be assigned)
    Available Formats: auto, common, apache, iis, ncsa, nginx, pws, sambar
    
-sn:[session name]  (if not used, "[unixtime]" will be assigned)

-hm:[method name]   Hunt Method (if not used, "normal" will be assigned)
    Available Methods:
    normal              All Attack Types (Standard Scan)
    reconstruct         Session Reconstruction (use with -sip)
                          (isolates all requests associated with an IP)
                          
-nv                 Turn off verbose. Error and basic info still gets printed

Other parameters:
-sip:[ip]           Target source IP address
-rip                Resolve attacker IP addresses (Slow)
-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list

  ]])
end

function addattack(t)
  local ipcountry = {}
  local printinfo = function(name,value)
    print('  '..name..': '..value)
  end
  if string.match(t.ip,'[:]') then
    ipcountry = geodb:search_ipv6(t.ip)
  else
    ipcountry = geodb:search_ipv4(t.ip)
  end
  if t.isbreach == false then
    cs.printgreen('Attack Found')
  else
    cs.printgreen('Breach Found')
  end
  printinfo('Attacker IP',t.ip)
  printinfo('Attack Description',t.description)
  if ipcountry ~= nil then
    printinfo('Attack Origin',ipcountry.country.names.en)
  else
    printinfo('Attack Origin','N/A')
  end
  if t.tooltitle ~= '' then
    printinfo('Tool',t.tooltitle)
  end
  printinfo('Date / Time',t.date)
  printinfo('Request',t.request)
  printinfo('Status',tostring(t.statuscode))
  printinfo('Line',tostring(t.line))
end

function printscanresult(i)
  if i.attackcount ~= 0 then
    cs.printred('ATTACK ATTEMPTS FOUND!')
  	if i.breached == true then
  	   cs.printred('WARNING: The web server has been breached!')
  	end
  	if i.huntmethod == 'reconstruct' then
    	 cs.printred(string.format(
    	  'Found %i possible attacks originating from IP: %s',
    	  i.attackcount,params.targetip))
    else
    	 cs.printred(string.format(
    	  'Found %i possible attacks originating from %i sources:',
    	  i.attackcount,i.sourcecount))
    	 cs.printred(i.attackerlist)
  	end
  else
  	cs.printgreen('No attacks found.')
  end
  if i.warnings ~= '' then
    cs.printred('showmsg',i.warnings)
  end
end

function startscan()
  print('________________________________________________________________\n')
  i = symini.insight:new()
  
  if hasarg('-nv') == false then
    i.onlogmessage = function(s) print(s) end
    i.onattackfound = addattack
  end

  -- Set the scanner preferences based on switches provided
  i.debug = hasarg('-dbg')
  i.resolveip = hasarg('-rip')
  i.sessionname = arg('sn',symini.getsessionname())
  i.huntmethod = arg('hm','normal')
  i.targetip = arg('sip','')
  i.logformat = arg('fmt','auto')
  
  -- Expecting a target like: c:\www\logs\access.log
  local target = arg(1)
  -- Expecting a target between quotes: "c:\web logs\access.log"
  if ctk.string.beginswith(target,'"') then
    target = ctk.string.after(arg(),'"')
    target = ctk.string.before(target,'"')
  end

  if i.targetip ~= '' then
    print('Reconstructing session for IP: '..i.targetip)
  end
  i:scanfile(target)
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