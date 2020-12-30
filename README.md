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

### Example usage

To set a domain e.g. `bork.olof.dev` to the current public IP you can write  
```
$ python3 loopiaupdate.py --credential "user@loopiaapi:MY_SUPER_SECRET_PASSWORD" bork.olof.dev
85.230.xxx.xxx
Response:OK,
```
.

Or, if you have a preferred ip-address you can use the `--ip` flag. Like this below
```
$ python3 loopiaupdate.py --credential "user@loopiaapi:MY_SUPER_SECRET_PASSWORD" --ip 1.2.3.4 bork.olof.dev
85.230.xxx.xxx
Response:OK,
```

The commands for creating a new subdomain are the same as above. The response is different though

```
python3 loopiaupdate.py --credential "user@loopiaapi:MY_SUPER_SECRET_PASSWORD" --ip 1.2.3.4 bork.xkz.se

Response:OK, OK,
```
since you have now two `OK` instead of just one. Which is because you are doing two operations: creating the subdomain and setting the domain into that ip-address.


## License
This program is protected by GNU General Public License 3.0, it means that you can't use this program in your propertiary code. Please read further in the COPYING file for more information on how it affects you.
