require "SyMini"
ctk = require "Catarinka"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg

if hasarg('-start') then
  local hs = symini.hybrid:new()
  hs:start()
  hs:scheduler_start()
  hs:release()
end