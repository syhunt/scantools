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

function starthide()
  symini.scheduler_start()
  print('Started.')
end

local cmd = {
 ['-about'] = function() print(symini.info.about) end,
 ['-help'] = printhelp,
 ['-start'] = starthide,
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or handleparams
cmd()