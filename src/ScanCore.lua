require "SyMini.Console"

ctk = require "Catalunya"
cs, arg, hasarg = ctk.cs, ctk.utils.getarg, ctk.utils.hasarg

print(string.format('SYHUNT CORE %s %s %s',
  symini.info.version, string.upper(symini.info.modename),
  symini.info.copyright))
  
function printhelp()
  local com = (symini.info.modename == 'Community Edition')
  print('________________________________________________________________\n')
  print([[
-stop                Stops all running processes from this Syhunt installation
-runcmd:[cmd]
  Available actions: 
  stop                Stops all running processes from this Syhunt installation
  clearinc            Clears the incremental cache (if any)
  clearpref           Clears the global preferences
  clearsite           Clears the site preferences (if any)
  cleartrack          Clears any added issue trackers
  update              Checks, downloads and install any updates
    If you are on Linux, use the scanupdate command instead.
-prefset:[key]       Update the value of a preference
    Requires -value or -fromfile parameter
    -v:[value]   Value to be set
    -fromfile:[filename] Reads the value contents from a file
    -vsecret optional parameter to hide input when entering password or any 
		sensitive information
    -vstring optional parameter that forces a value as string
    -tg:[url] optional parameter that allows to set the value as a site preference
-prefprint:[key]     Prints the current value of a preference    
    -tg:[url] optional parameter that allows to read the value as a site preference
  ]])  
  -- Switches below will not work in Community Edition
  if com == false then
    print([[
-ptkset:[key]        Updates your Pen-Tester Key
-ptkset:[filename]   Updates your Pen-Tester Key from a file
-ptkinfo             Displays details about your Pen-Tester Key
-apikeyinfo          Displays details about your Web API Key (if previously generated)
-apikeygen           Generates or re-generates the Web API key
-apisignal:[signal]  Sends a signal to the web API server
	Available signals: start, stop, quit
-tracker:[action]    Allows to perform various issue tracker related operations
    Available actions: add, set, send, del or list
    add  - Adds a new tracker (GitHub, GitLab, etc)
    set  - Sets the value of a preference key to the issue tracker preferences
		Requires -to, -key and -value parameters
		-to:[trackername]		
		-key:[keyname] Example: api.auth.token
		-v:[value]
		-vsecret optional parameter to hide input when entering password or any 
		sensitive information
        -vstring optional parameter that forces a value as string
    send - Sends details about a vulnerability to the issue tracker
		Requires -tid and -to parameters
		-tid:[trackid] Vulnerability track ID from report
		               Use TEST as trackid to submit a test issue
		-to:[trackername]               
		-note:"[yourcomment]" optional parameter to add a user note to its details
		Usage Example:
		scancore -tracker:send -to:myproject -tid:1596281007-7-4771
    del  - Deletes a tracker by its name
        Requires -name:[trackername] parameter
    list - Lists all available issue trackers		
-impdump:[filename]   Imports an Icy Dark dump file
-checks               Exports Syhunt Checks list
-checkupd             Checks for Updates
  ]])
  end
  print([[
-about                Displays information on the current version of Syhunt
-help (or /?)         Displays this list
  ]])
end  

-- Handles tracker parameter
function trackerexists(hs, trackername, warn)
  warn = warn or false
  local b = hs:tracker_exists(trackername)
  if warn == true then
    if b == false then
      cs.printred('Tracker not found: '..trackername)   
    end
  end
  return b
end

function handleimportdump(filename)
  local id = symini.icydark:new()
  id:start()
  local imp = id:importdump(filename)
    if imp.b == false then
      cs.printred(imp.s)  
    else
      cs.printgreen(imp.s)    
    end
  id:release()
end

function handletracker(action)
  local hs = symini.hybrid:new()
  hs:start()
  if action == 'list' then
    print(hs:tracker_getlistdetailed())
  end
  if action == 'del' then
    local trackername = arg('name','')  
    if trackerexists(hs, trackername, true) then
      hs:tracker_delete(trackername)
    end
  end
  if action == 'add' then
    print('Enter the name of the tracker you want to add:')
    local trackername = cs.readln() 
    if trackerexists(hs, trackername) then
      cs.printred('A tracker with this name already exists.')    
    else
      print('Enter the tracker type:')
      print('		Available types are: GitHub, GitLab, JIRA or Email')
      local trackertype = cs.readln()
      print('Adding tracker...')
      local res = hs:tracker_add(trackername, trackertype)
      if res.success == true then
        cs.printgreen(res.resultstr)
      else
        cs.printred(res.resultstr)
      end      
    end
  end
  if action == 'set' then
    local trackername = arg('to','')
    if trackerexists(hs, trackername, true) then
      local keyname = arg('key','')
      local value = arg('v','')
       if hasarg('-vsecret') then
        print('Enter '..keyname..':')
        value = cs.readpwd()
       end
       if hasarg('-vstring') == false then
        value = symini.strtocidvalue(value)
       end   
       local res = hs:tracker_setvalue(trackername, keyname, value)
       if res.success == true then
         cs.printgreen(res.resultstr)
       else
         cs.printred(res.resultstr)
       end
    end  
  end
  if action == 'send' then
        local trackername = arg('to','')
        if trackerexists(hs, trackername, true) then        
          local tid = arg('tid','')
          local issue = hs:tracker_getissuebyid(tid, arg('note',''))
          if issue.valid == true then
            issue.tracker = trackername
            local res = hs:tracker_sendissue(issue)
            if res.alreadysent == true then
              print('Already sent!')
            end
            if res.success == true then
              cs.printgreen('Success')
            else
              cs.printred('Error: '..res.errormsg)
              if tid == 'debug' then
                cs.printred(res.debuglog)
              end
            end
          else
            cs.printred('Invalid vulnerability track ID: '..tid)
          end  
        end
  end
  hs:release()
end

function printresult(res)
  if res.result == true then
    cs.printgreen(res.resultstr)
  else
    cs.printred(res.resultstr)    
  end
end

function setprefvalue(key,value)
  printresult(symini.prefs_set(key,value,arg('tg','')))
end

function handleparams()
  print('________________________________________________________________\n')
  if hasarg('-runcmd') then
    printresult(symini.runcmd(arg('runcmd','')))
  end
  if hasarg('-printinfo') then
    print(symini.info[arg('printinfo','')])
  end  
  if hasarg('-ptkset') then
    printresult(symini.setptk(arg('ptkset','')))
  end
  if hasarg('-ptkinfo') then
    print(symini.getptkdetails('text'))
  end
  if hasarg('-prefset') then
    local keyname = arg('prefset','')
    local hasvalue = false
    local value = ''
    if hasarg('-v') then 
      hasvalue = true
      value = arg('v','')
    end
    if hasarg('-vsecret') then
      print('Enter '..keyname..':')
      hasvalue = true      
      value = cs.readpwd()
    end
    if hasarg('-fromfile') then
      local fn = arg('fromfile','')
      if ctk.file.exists(fn) then
        hasvalue = true
        value = ctk.file.getcontents(fn)
      else
        cs.printred('Error: input file not found.')
      end    
    end
    if hasvalue == true then
      if hasarg('-vstring') == false then
        value = symini.strtocidvalue(value)
      end   
      setprefvalue(keyname,value)
    else
      cs.printred('Error: missing value parameter.')
    end
  end    
  if hasarg('-prefprint') then  
    printresult(symini.prefs_get(arg('prefprint',''),arg('tg','')))
  end
  if hasarg('-apisignal') then
    print(arg('apisignal',''))
    symini.sendwebapisignal(arg('apisignal',''))
  end    
  if hasarg('-apikeyinfo') then
    print(symini.getptkdetails().webapikey)
  end    
  if hasarg('-apikeygen') then
    printresult(symini.genwebapikey())
  end
  if hasarg('-tracker') then
    handletracker(arg('tracker','list'))
  end
  if hasarg('-impdump') then
    handleimportdump(arg('impdump',''))
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

-- Warning: this command must only be called by the Syhunt setup. If you call it
-- you will have to reinstall Syhunt.
function cleancarbon()
  print('Cleaning Carbon installation...')
  symini.runcmd('cleancarbon')
  stop()
end  

function checkforupdates()
  local stat = symini.checkinst('update')
  if stat.veruptodate == true then
    cs.printgreen(stat.verstatustext)
  else
    cs.printred(stat.verstatustext)
  end
end
  
local cmd = {
 ['-checks'] = printchecks, 
 ['-about'] = function() print(symini.info.about) end,
 ['-help'] = printhelp,
 ['-stop'] = stop,
 ['-checkupd'] = checkforupdates, 
 ['-cleancarbon'] = cleancarbon, 
 ['/?'] = printhelp,
 [''] = printhelp
}
cmd = cmd[arg()] or handleparams
cmd()