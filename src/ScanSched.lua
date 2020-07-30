require "SyMini.Console"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg

print(string.format('SYHUNT SCAN SCHEDULER %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))
  
function printhelp()
  print('________________________________________________________________\n')
  print([[
-list               Lists the scheduled scans
-start              Starts the scheduler as a background process
-stop               Stops the scheduler process (if running)
-update             Updates scheduled events (if any)
-help (or /?)       Displays this list
  ]])
end

function handleparams()
  print('________________________________________________________________\n')
  local hs = symini.hybrid:new()
  hs:start()
  hs.onlogmessage = function(s) print(s) end
  if hasarg('-list') then
    hs:scheduler_listscheduledscans()
  end
  hs:release()
end

function sendsignal(signal)
  local res = symini.scheduler_sendsignal(signal)
  if res.result == true then
    cs.printgreen(res.resultstr)
  else
    cs.printred(res.resultstr)  
  end
end

local cmd = {
 ['-about'] = function() print(symini.info.about) end,
 ['-help'] = printhelp,
 ['-start'] = function() sendsignal('start') end,
 ['-stop'] = function() sendsignal('stop') end, 
 ['-update'] = function() sendsignal('update') end, 
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or handleparams
cmd()