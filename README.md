Simple TPM PK11
===============

A simple library for using the TPM chip to secure SSH keys.

Copyright 2013 Google Inc. All Rights Reserved.
Apache 2.0 license.

This is NOT a Google product.

Contact: thomas@habets.se / habets@google.com  
https://github.com/ThomasHabets/


Install dependencies
--------------------
Debian:
```
apt-get install tpm-tools libtspi-dev libopencryptoki-dev libssl-dev
```
Fedora:
```
tpm-tools
opencryptoki-devel
trousers-devel
openssl-devel
```


Build simple-tpm-pk11
---------------------
```
./bootstrap.sh && make && sudo make install
```


Init TPM chip
-------------
1. If you have not taken ownership, do so.
```
tpm_takeownership -z
Enter owner password: [enter something secret here]
Confirm password: [enter something secret here]
```

2. SRK password is usually the Well Known Secret (all nulls). You can
   specify a password but it's easier it you don't. The SRK password is only
   used to allow crypto operations. You still need blobs and key passwords to
   use other peoples keys.
```
tpm_changeownerauth -s -r
```

If you get any error messages, see read TPM-TROUBLESHOOTING.

User setup
----------

### 1. Create key
```
mkdir ~/.simple-tpm-pk11/
stpm-keygen -o ~/.simple-tpm-pk11/my.key
```

(use `-p` if you want to set a password on the key)

Try out the key:
```
dd if=/dev/urandom of=to-sign bs=1 count=35
stpm-sign -k ~/.simple-tpm-pk11/my.key -f to-sign
```

### 2. Create config
```
echo "key my.key" > ~/.simple-tpm-pk11/config
```

Optionally add "log foo.log" in there too.


### 3. Extract the public key in SSH format
```
ssh-keygen -D libsimple-tpm-pk11.so
```

Install it where you want to log in, in the usual authorized_keys way.

Try logging in using your new fancy key:
```
ssh -I libsimple-tpm-pk11.so shell.example.com
```

### 4. Configure SSH to always use this module
Add this to `~/.ssh/config`:
```
Host *
      PKCS11Provider libsimple-tpm-pk11.so
```

then try:
```
ssh shell.example.com
```


Tested with
-----------

### Machines
* Lenovo T410 / STM TPM 1.2.8.16
* Lenovo T500 / INTC STM 1.2.4.1
* Dell Precision T3500 / WEC TPM 1.2.2.81
* Lenovo T440s / STM TPM 1.2.13.12
* Lenovo X240 / STM TPM 1.2.13.12
* Lenono X200s / INTC TPM 1.2.4.1

### Software
* OpenSSH 6.0p1 on Debian 7.2
* OpenSSH 5.9
* OpenSSH 6.4p1 on CentOS 7.0
* OpenSSH 6.8p1 on Arch Linux


TODO
----
* Clean up code.
* config option: log to stdout and/or stderr in addition to logfile.
* Install in the correct place.
* Add PKCS11 support to ssh *server*.
* Global config in /etc.
* Optionally stir with /dev/random when generating keys.
* Script to automate setting up, including verifying TPM state and fixing it.
* Auto-generate keys on demand? Or should this only be part of script to set up?
* Make it work with gpg, and document.
* Make it work with SSH certs, and document.
* Make it work with openssl, and document.
* Make it work with Firefox, and document.
* Make it work with Chrome, and document.
* Make it work with encrypted home directories, and document.


Reference links
---------------
* http://secgroup.ext.dsi.unive.it/projects/security-apis/tookan/
* http://secgroup.ext.dsi.unive.it/projects/security-apis/cryptokix/
* http://trousers.sourceforge.net/pkcs11.html
* http://www.trustedcomputinggroup.org/resources/tcg_software_stack_tss_specification
* http://www.infineon.com/dgdl/TPM+Key+Backup+and+Recovery.pdf
* http://www.engadget.com/2010/02/12/christopher-tarnovsky-hacks-infineons-unhackable-chip-we-pre/
* http://trousers.sourceforge.net/dev_faq.html
* http://resources.infosecinstitute.com/linux-tpm-encryption-initializing-and-using-the-tpm/
* http://p11-glue.freedesktop.org/p11-kit.html
* http://trousers.sourceforge.net/dev_faq.html


Make new release
----------------
* Update configure.ac with new version, commit.
* git tag -a -s 0.0x
* git push --tags


Some random notes, not instructions
-----------------------------------
```
openssl genrsa -out rsa-key 2048
openssl rsa -in rsa-key -modulus
exponent is always 65537.
ssh-keygen -f rsa-key -y > rsa-key.pub
```
