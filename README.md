```
▓█████▄  ▄▄▄       ███▄    █   ▄████  ██▓     ██▓ ███▄    █   ▄████              
▒██▀ ██▌▒████▄     ██ ▀█   █  ██▒ ▀█▒▓██▒    ▓██▒ ██ ▀█   █  ██▒ ▀█▒             
░██   █▌▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒██░    ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░             
░▓█▄   ▌░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓▒██░    ░██░▓██▒  ▐▌██▒░▓█  ██▓             
░▒████▓  ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒░██████▒░██░▒██░   ▓██░░▒▓███▀▒             
 ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒ ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒              
 ░ ▒  ▒   ▒   ▒▒ ░░ ░░   ░ ▒░  ░   ░ ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░  ░   ░              
 ░ ░  ░   ░   ▒      ░   ░ ░ ░ ░   ░   ░ ░    ▒ ░   ░   ░ ░ ░ ░   ░              
   ░          ░  ░         ░       ░     ░  ░ ░           ░       ░              
 ░                                                                               
                                  ▄████▄   ███▄    █  ▄▄▄       ███▄ ▄███▓▓█████ 
                                 ▒██▀ ▀█   ██ ▀█   █ ▒████▄    ▓██▒▀█▀ ██▒▓█   ▀ 
                                 ▒▓█    ▄ ▓██  ▀█ ██▒▒██  ▀█▄  ▓██    ▓██░▒███   
                                 ▒▓▓▄ ▄██▒▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██    ▒██ ▒▓█  ▄ 
                                 ▒ ▓███▀ ░▒██░   ▓██░ ▓█   ▓██▒▒██▒   ░██▒░▒████▒
                                 ░ ░▒ ▒  ░░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒░   ░  ░░░ ▒░ ░
                                   ░  ▒   ░ ░░   ░ ▒░  ▒   ▒▒ ░░  ░      ░ ░ ░  ░
                                 ░           ░   ░ ░   ░   ▒   ░      ░      ░   
                                 ░ ░               ░       ░  ░       ░      ░  ░
                                 ░                                               
  
 ```
 # What is this?
 
 Dangling CNAME checks a given domain for dangling CNAMEs on a given DNS zone. 
 When a DNS zone points a CNAME to another domain that the attacker can (partially) control, the attacker can have host arbitrary content with the victim's DNS zone. Consider a CNAME that points to an Azure load balancer - ".trafficmanager.net". When you decomission that load balancer configuration, the CNAME remains and an attacker can register their own. 
An [example unfortunate incident is described by The Register](https://www.theregister.co.uk/2020/05/06/pwc_azure_squatting/)


You can use arbitrary list of records to check (e.g. feed in from dnsrecon), use [crt.sh](https://crt.sh) certificate transparency store or [DNSDB](https://www.dnsdb.info) (a paid service).
# Usage:
```
$ ./danglingcname --help
Usage of ./danglingcname:
  -debug
    	Debug mode
  -dnsdb
    	Use DNSDB (set DNSDB_KEY env var) (Optional)
  -domain string
    	Target domain.
  -server string
    	DNS Server. (Optional) (default "8.8.8.8:53")
  -sourcefile string
    	Specify a source file to read DNS records, one per line (Optional)
  -usecrtsh
    	Use crt.sh as source
  -workers int
    	Number of workers (Optional) (default 5)
```

# Example
```
./danglingcname -usecrtsh -workers 5 -server 172.31.0.1:53 -domain pwc.com
INFO[0000] Sucesfully fetched from crt.sh pwc.com  
...
```
