# p1-creatersakeys
Using JCProv, a library provided by Gemalto, this program creates RSA Keys within the Luna HSMs.

## Eclipse Project:
This project is being provided with the whole Eclipse Project folder.
In order to compile using Eclipse IDE, you need:
- Copy folder LIBRARIES to C:\ **OR** modify file .classpath in order to find the required libraries.
- On Eclipse, check if External Jars (commons-cli-1.3.1.jar, commons-codec-1.10.jar and jcprov.jar) are there (see file **eclipse1.png** for more information)

## Pre-requisites:
- To have Luna client installed
- Partition assigned to the client
- Check your slot list using:
```
vtl listslots
Number of slots: 1

The following slots were found:

Slot Description          Label                            Serial #         Status
==== ==================== ================================ ================ ============
   0 Net Token Slot       partition-01                     3423358          Present
```
On the above output, my target Slot = 0.
   
   

## Using:
- Go to Folder PprjRsaKeys\jar-git
- On the command prompt, run:
```
** java -jar CreateRsaKeys.jar <OPTIONS> **
```

## Help
Getting help:
```
** java -jar CreateRsaKeys.jar **

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
CreateRsaKeys
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

usage: CreateRsaKeys [-k <arg>] [-p <arg>] [-pr <arg>] [-pu <arg>] [-s <arg>] [-sa <arg>]

 -k,--keySize <arg>            Valid sizes: [512, 1024, 2048, 3072, 4096, 8192]
 -p,--password <arg>           partition password
 -pr,--privateKeyLabel <arg>   Valid chars: [a-z, A-Z, 0-9, -, _, .]
 -pu,--publicKeyLabel <arg>    Valid chars: [a-z, A-Z, 0-9, -, _, .]
 -s,--slot <arg>               slot identifier
 -sa,--salt <arg>              yes / no
```

## Example 1
```
** java -jar CreateRsaKeys.jar -s 0 -p Password#123 -k 2048 -sa yes -pr MY-PRIVATE -pu MY-PUBLIC **

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
CreateRsaKeys
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Session Opened
Login finished
Private key with the given label already exists?
**>No, we are good to proceed**
Starting Generate Key Pair process
Salt is ON
Calling GenerateKeyPair method
**>Keys generated sucessfully**
Private key is in the HSM? Let me check...
**>Yes, it is!**
Finished key pair generation.
Logout done
Session closed
Library finalized
```

As you can see, the program points step-by-step what it is doing, so you can easily see how the interaction is happening.

## Example 2
Although HSM permits to create inumerous keys with same Label, that is not permitted using this program.
In case you try to create a RSA Private Key with the same name, the below error will be shown:
```
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
CreateRsaKeys
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Session Opened
Login finished
Private key with the given label already exists?
**>Private Key with the label MY-PRIVATE already exists, aborting key pair generation**
Logout done
Session closed
Library finalized
```

## Final checking
If you wish to check whether the created keys are in the HSM, run the below command provided by Luna client:
```
**cmu list**

Select token
 [0] Token Label: partition-01
 
 Enter choice: 0
Please enter password for token in slot 0 : ********
handle=123      label=MY-PUBLIC
handle=126      label=MY-PRIVATE
```

## Getting Professional Support
Email to: supercrypto.contact@gmail.com
