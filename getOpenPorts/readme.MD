# Get open Ports

Usage of bin/qualys-openports:
  -base-url string
    	Qualys API base URL
  -batch
    	Batch mode: use IN operator
  -ip string
    	Single IP to lookup
  -ip-file string
    	File with one IP per line
  -port int
    	If non-zero, only show this port
  -timeout duration
    	HTTP timeout (default 30s)
  -token string
    	Qualys JWT token (optional)

take an IP or IP file and return ports on that IP from Qualys CSAM.

