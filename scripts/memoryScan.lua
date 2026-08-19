// LIBRARY
metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then exit("Unable to find metaxploit.so")

// Parameters
if params.len != 2 or params[0] == "-h" then exit("Usage: memoryScan <IP> <PORT>")

address = params[0]
port = params[1].to_int

// Null Session
net_session = metaxploit.net_use(address,port)
if not net_session then exit("Couldn't start null session on the target")

// Metalib detection
metalib = net_session.dump_lib
scan_ = metaxploit.scan(metalib)
if not scan_ then exit("No service detected")

// Memory analisys
for entry in scan_
	memory_scan = metaxploit.scan_address(metalib,entry)
	print(entry+"\n"+memory_scan)  
end for

// Service Name and Version
print(metalib.lib_name+" v"+metalib.version)
