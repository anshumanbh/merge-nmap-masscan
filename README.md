# merge-nmap-masscan

A quick and ditry utility that can be used for merging NMAP's CSV file (Use [this](https://github.com/anshumanbh/nmapxmltocsv) to convert NMAP XML to CSV) and Masscan's List file (use the -oL flag to generate a list file for masscan output) into one consolidated CSV file to be used in other automation and workflows.

NMAP file looks like this:
```
Hostname,IPAddress,Port,Protocol,Servicename,Servicestate
anshumanbhartiya.com,104.198.14.52,80,tcp,tcpwrapped,open
anshumanbhartiya.com,104.198.14.52,443,tcp,tcpwrapped,open
anshumanbhartiya.com,104.198.14.52,4443,tcp,tcpwrapped,open
github.anshumanbhartiya.com,185.199.110.153,80,tcp,tcpwrapped,open
github.anshumanbhartiya.com,185.199.110.153,443,tcp,tcpwrapped,open
yolo.anshumanbhartiya.com,1.2.3.4,999,tcp,tcpwrapped,open
```

Masscan file looks like this:
```
#masscan
open tcp 43 104.198.14.52 1529229065
open tcp 443 185.199.110.153 1529229065
open tcp 4443 104.198.14.52 1529229065
open tcp 80 104.198.14.52 1529229065
open tcp 80 185.199.110.153 1529229065
open tcp 8000 185.199.110.153 1529229065
open tcp 8080 1.2.3.4 1529229065
open tcp 8080 104.198.14.52 1529229065
open tcp 8800 185.199.110.153 1529229065
# end
```

The final merged file will look like this:
```
Hostname,IPAddress,Port,Protocol,Servicename,Servicestate
anshumanbhartiya.com,104.198.14.52,80,tcp,tcpwrapped,open
anshumanbhartiya.com,104.198.14.52,443,tcp,tcpwrapped,open
anshumanbhartiya.com,104.198.14.52,4443,tcp,tcpwrapped,open
github.anshumanbhartiya.com,185.199.110.153,80,tcp,tcpwrapped,open
github.anshumanbhartiya.com,185.199.110.153,443,tcp,tcpwrapped,open
yolo.anshumanbhartiya.com,1.2.3.4,999,tcp,tcpwrapped,open
anshumanbhartiya.com,104.198.14.52,43,tcp,NA,open
github.anshumanbhartiya.com,185.199.110.153,8000,tcp,NA,open
yolo.anshumanbhartiya.com,1.2.3.4,8080,tcp,NA,open
anshumanbhartiya.com,104.198.14.52,8080,tcp,NA,open
github.anshumanbhartiya.com,185.199.110.153,8800,tcp,NA,open
```

The above masscan and nmap files are provided with the repo and the Docker image as well!!

## Running
Either run with defaults - `go run main.go`

OR 

Specify the files - `go run main.go -masscanFile <> -nmapFile <> -outFile <>`

### Don't have GO? Use Docker instead
`docker run -it abhartiya/tools_mergenmapmasscan`

