require "SyMini.Console"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg

print(string.format('SYHUNT CORE %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))
  
function printhelp()
  local com = (symini.info.modename == 'Community Edition')
  print('________________________________________________________________\n')
  print([[
-stop               Stops all running processes from this Syhunt installation
  ]])  
  -- Switches below will not work in Community Edition
  if com == false then
    print([[
-ptkset:[key]       Updates your Pen-Tester Key
-ptkinfo            Displays details about your Pen-Tester Key
-apikeyinfo         Displays details about your Web API Key (if previously generated)
-apikeygen          Generates or re-generates the Web API key
-apisignal:[signal] Sends a signal to the web API server
	Available signals: start, stop, restart
-checks             Exports Syhunt Checks list
  ]])
  end
  print([[
-about              Displays information on the current version of Syhunt
-help (or /?)       Displays this list
  ]])
end  

function handleparams()
  print('________________________________________________________________\n')
  if hasarg('-ptkset') then
    local res = symini.setptk(arg('ptkset',''))
    if res.result == true then
      cs.printgreen(res.resulttext)
    else
      cs.printred(res.resulttext)    
    end
  end
  if hasarg('-ptkinfo') then
    print(symini.getptkdetails('text'))
  end
  if hasarg('-apisignal') then
    print(arg('apisignal',''))
    symini.sendwebapisignal(arg('apisignal',''))
  end    
  if hasarg('-apikeyinfo') then
    print(symini.getptkdetails().webapikey)
  end    
  if hasarg('-apikeygen') then
    local res = symini.genwebapikey()
    if res.result == true then
	  cs.printgreen(res.key) 
	else
	  cs.printred('Make sure the web API server is running.')
	end
  end     
end

function printchecks()
  local hs = symini.hybrid:new()
  hs.onlogmessage = function(s) print(s) end
  hs:start()
  hs:getchecklist()
  hs:release()
end
  
function stop()
  print('Closing running tasks...')
  symini.runcmd('stop')
  print('Done.')
end  
  
local cmd = {
 ['-checks'] = printchecks, 
 ['-about'] = function() print(symini.info.about) end,
 ['-help'] = printhelp,
 ['-stop'] = stop,
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or handleparams
cmd()