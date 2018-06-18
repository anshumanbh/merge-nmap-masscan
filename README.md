# merge-nmap-masscan

A quick and ditry utility that can be used for merging NMAP's CSV file (Use [this](https://github.com/anshumanbh/nmapxmltocsv) to convert NMAP XML to CSV) and Masscan's List file (use the -oL flag to generate a list file for masscan output) into one consolidated CSV file to be used in other automation and workflows.

The final merged file looks like this:
```
Hostname,IPAddress,Port,Protocol,Servicename,Servicestate
anshumanbhartiya.com,104.198.14.52,80,tcp,tcpwrapped,open
anshumanbhartiya.com,104.198.14.52,443,tcp,tcpwrapped,open
github.anshumanbhartiya.com,185.199.110.153,80,tcp,tcpwrapped,open
github.anshumanbhartiya.com,185.199.110.153,443,tcp,tcpwrapped,open
NA,185.199.112.153,80,tcp,NA,open
github.anshumanbhartiya.com,185.199.110.153,8000,tcp,NA,open
```

Sample masscan and nmap files are provided!!

## Running
Either run with defaults - `go run main.go`

OR 

Specify the files - `go run main.go -masscanFile <> -nmapFile <> -outFile <>`

### Don't have GO? Use Docker instead
`docker run -it abhartiya/tools_mergenmapmasscan`

