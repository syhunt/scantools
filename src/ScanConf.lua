require "SyMini"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg

print(string.format('SYHUNT HARDEN %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))

function printhelp()
  cs.printwhite('Type scanconf -about for more information.')
  print('________________________________________________________________\n')
  print([[
Usage: scanconf [server conf or INI file] [optional params]
Examples: 
    scanconf c:\www\conf\httpd_conf.conf
    scanconf c:\httpd\php\php.ini
    scanconf "c:\web server\conf\httpd_conf.conf"
    
-sn:[session name]  (if not used, "[unixtime]" will be assigned)

Other parameters:
-noid               Enables the Paranoid scan mode
                      (recommended only for advanced users)
-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list
  ]])
end

function printrecom(r)
  if r.line ~= -1 then
    cs.printgreen(string.format('Found: %s on line %s',r.name,r.line))
  else
    cs.printgreen(string.format('Not Found: %s',r.name))
  end
  print(string.format('   Details: %s',r.desc))
end

function printscanresult(hd)
  if hd.recomcount ~= 0 then
   	if hd.recomcount == 1 then
  		cs.printred('1 security recommendation.')
  	else
	  	cs.printred(string.format('%i security recommendations.',hd.recomcount))
	  end
  else
		cs.printgreen('No security recommendations.')
  end
end

function startscan()
  print('________________________________________________________________\n')
  local hd = symini.hardener:new()
  hd.onlogmessage = function(s) print(s) end
  hd.onrecom = printrecom

  -- Set the scanner preferences based on switches provided
  hd.sessionname = arg('sn',symini.getsessionname())
  hd.debug = hasarg('-dbg')
  hd.paranoid = hasarg('-noid')
  
  -- Expecting a target like: scanconf httpd_conf.conf
  local target = arg(1)
  -- Expecting a target between quotes: "httpd conf.conf"
  if ctk.string.beginswith(target,'"') then
    target = ctk.string.after(arg(),'"')
    target = ctk.string.before(target,'"')
  end
  
  if ctk.file.exists(target) then
    hd:scanfile(target)
    printscanresult(hd)
  else
    cs.printred(string.format('File %s not found.',target))
  end
  print('Done.')
  
  hd:release()
end

local cmd = {
 ['-about'] = function() print(symini.info.about) end,
 ['-help'] = printhelp,
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or startscan
cmd()