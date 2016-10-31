# loopiaupdate

This python script 'loopiaupdate' retrieves the ip and updates a given domain 
or subdomain using the Loopia domain api interface.

This script have some nice features e.g. it will add subdomain if it does not
exist.

## Usage

### Preparation
Create a LoopiaAPI account with following permissions:
* addSubdomain
* updateZoneRecord
* addZoneRecord
* getSubdomains
* getZoneRecords

Now you got two options... Either you create a credential file with your
authentication information OR append username and password in the command.
(this is NOT recommended if you are using a shared computer)

### How to create a credential file
Create ~/.loopiaupdate/credentials in $HOME with following content:
```
username=user@loopiaapi
password=pw
```
...where 'user' is, of course, the loopiaapi username you created at loopia. 

### Syntax

```
python3 loopiaupdate.py [-h] [-u username -p password] [--ip 1.2.3.4] <domain>
```

## License
GPL v3
