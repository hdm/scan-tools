description = [[
A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within five seconds.
If no banner is received, a HTTP GET request is sent and the response recorded. Banners which contain telnet sequences will trigger
telnet option negotiation, with the intent to get far enough into the handshake that we can receive the real banner. If data is 
received, more data will be read for up to fifteen seconds.

]]

---
-- @output
-- 21/tcp open  ftp
-- |_ banner-plus: 220 FTP version 1.0\x0D\x0A


author = "hdm"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local nmap   = require "nmap"
local comm   = require "comm"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local nsedebug = require "nsedebug"

---
-- Script is executed for any TCP port.
portrule = function( host, port )
  return port.protocol == "tcp"
end


---
-- Grabs a banner and outputs it nicely formatted.
action = function( host, port )
  local out = grab_banner(host, port)
  return output( out )
end


---
-- Go through telnet's option palaver so we can get to the login prompt.
-- We just deny every options the server asks us about.
-- Stolen entirely from telnet-brute.nse with tweaks
local negotiate_options = function(result, soc)

	local index, x, opttype, opt, retbuf, data
	count = 0
	index = 0
	retbuf = strbuf.new()

	while count < 20 do

		-- 255 is IAC (Interpret As Command)
		index, x = string.find(result, '\255', index)

		if not index then 
			break 
		end

		opttype = string.byte(result, index+1)
		opt = string.byte(result, index+2)

		-- don't want it! won't do it! 
		if opttype == 251 or opttype == 252 then
			opttype = 254
		elseif opttype == 253 or opttype == 254 then
			opttype = 252
		end

		retbuf = retbuf .. string.char(255)
		retbuf = retbuf .. string.char(opttype)
		retbuf = retbuf .. string.char(opt)
		index = index + 1
		count = count + 1
	end	
	
	local data = strbuf.dump(retbuf)
	if data:len() > 0 then	
	    soc:send(data)
	end
end

---
-- Returns a number of milliseconds for use as a socket timeout value (defaults to 5 seconds).
--
-- @return Number of milliseconds.
function get_timeout()
  return 5000
end



---
-- Connects to the target on the given port and returns any data issued by a listening service.
-- @param host  Host Table.
-- @param port  Port Table.
-- @return      Socket descriptor and initial banner
function grab_banner(host, port)

  local st, buff, banner
  local pnum = port.number
  local probe = "GET / HTTP/1.1\r\nHost: www\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0\r\n\r\n"

  local proto  = "tcp"
  local socket = nmap.new_socket()  
  socket:set_timeout(get_timeout())
  
  banner = ""
  
  if pnum == 443 then
    proto = "ssl"
  end  
  
  st = socket:connect(host, port, proto)
  if not st then
    if proto == "ssl" then
      -- Fall back to non-SSL if our guess was wrong
      proto = "tcp"
    else
      -- Could not connect to the TCP port as a plain socket
      socket:close()
      return nil
    end
    st = socket:connect(host, port, proto)
    -- Give up if the second try fails
    if not st then
      socket:close()
      return nil
    end
  end
  
  local probe_sent = 0
  if pnum == 80 or pnum == 443 or pnum == 8080 then
    socket:send("GET / HTTP/1.0\r\n\r\n")
    probe_sent = 1
  end
  
  st, buff = socket:receive()
  if st then
    banner = banner .. buff
  end
  
  -- Send a probe if no banner was recieved
  if not st then
    socket:send(probe)
    probe_sent = 1  
    st, buff = socket:receive_bytes(1)
    if st then
      banner = banner .. buff 
    end
  end
  
  -- Flip SSL states and try again
  if not st then
    socket:close()
    
    if proto == "ssl" then
      proto = "tcp"
    else
      proto = "ssl"
    end

    st = socket:connect(host, port, proto)
    if not st then
      socket:close()
      return nil
    end

    st, buff = socket:receive()
    if st then
      banner = buff
    else
      socket:send(probe)
      probe_sent = true
      st,buff = socket:receive() 
      if st then  
        banner = banner .. buff       
      end
    end
  end
  
  if not st then
    socket:close()
    return nil
  end
 
 
  negotiate_options(banner, socket)
    
  -- Echo the original banner back to avoid ugly logs in SSH
  if string.find(banner, '^SSH-') then
    socket:send(banner)
  end
  
  -- This matches on both FTP and SMTP
  if string.find(banner, '^220 ') or string.find(banner, '^220-' ) then
    if string.find(banner, 'FTP') or pnum == 21 then
      socket:send("USER ftp\r\n")
      socket:send("PASS ftp@example.org\r\n")
    else
      socket:send("EHLO mail\r\n")
	end

    stdnse.sleep(1)
    socket:send("HELP\r\n")    
    stdnse.sleep(1)
    socket:send("QUIT\r\n")
  end

  socket:set_timeout(1000)
  
  local cnt = 0
  
  for cnt=1,15 do
    st,more = socket:receive_bytes(8192)
    if not st then
      break
    end
    
    negotiate_options(more, socket)
    banner = banner .. more
  end
  
  return banner
end

---
-- Formats the banner for printing to the port script result.
--
-- Non-printable characters are hex encoded and the banner is
-- then truncated to fit into the number of lines of output desired.
-- @param out  String banner issued by a listening service.
-- @return     String formatted for output.
-- Ripped from banner.nse with line wrap disabled (corrupts output)
function output( out )

  if type(out) ~= "string" or out == "" then return nil end

  local filename = SCRIPT_NAME
  local line_len = 75    -- The character width of command/shell prompt window.
  local fline_offset = 5 -- number of chars excluding script id not available to the script on the first line

  -- number of chars available on the first line of output
  -- we'll skip the first line of output if the filename is looong
  local fline_len
  if filename:len() < (line_len-fline_offset) then
    fline_len = line_len -1 -filename:len() -fline_offset
  else
    fline_len = 0
  end

  -- number of chars allowed on subsequent lines
  local sline_len = line_len -1 -(fline_offset-2)

  -- replace non-printable ascii chars - no need to do the whole string
  out = replace_nonprint(out, (out:len() * 3) + 1) -- 1 extra char so we can truncate below.

  -- break into lines - this will look awful if line_len is more than the actual space available on a line...
  local ptr = fline_len
  local t = {}
  t[#t+1] = out

  return table.concat(t,"\n")

end



---
-- Replaces characters with ASCII values outside of the range of standard printable
-- characters (decimal 32 to 126 inclusive) with hex encoded equivalents.
--
-- The second parameter dictates the number of characters to return, however, if the
-- last character before the number is reached is one that needs replacing then up to
-- three characters more than this number may be returned.
-- If the second parameter is nil, no limit is applied to the number of characters
-- that may be returned.
-- @param s    String on which to perform substitutions.
-- @param len  Number of characters to return.
-- @return     String.
-- Pulled from banner.nse and mangled to escape \r\t\n separately
function replace_nonprint( s, len )

  local t = {}
  local count = 0

  for c in s:gmatch(".") do
    if c:byte() == 9 then
      t[#t+1] = ("\\%s"):format("t")
      count = count+3
    elseif c:byte() == 10 then
      t[#t+1] = ("\\%s"):format("n")
      count = count+3     
    elseif c:byte() == 13 then
      t[#t+1] = ("\\%s"):format("r")
      count = count+3            
    elseif c:byte() < 32 or c:byte() > 126 then
      t[#t+1] = ("\\x%s"):format( ("0%s"):format( ( (stdnse.tohex( c:byte() )):upper() ) ):sub(-2,-1) ) -- capiche
      count = count+4
    else
      t[#t+1] = c
      count = count+1
    end
    if type(len) == "number" and count >= len then break end
  end

  return table.concat(t)

end
