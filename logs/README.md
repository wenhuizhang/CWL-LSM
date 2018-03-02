# Information 

## 1. How to access VM

Once logged on the bus, info for VM is listed as below:

VM Name: cse544_15

User: cse544

Password: cse544!proj3ct

```
$ virsh dumpxml cse544_15 | grep address
$ arp -n | grep 52:54:00:63:bf:87
$ ssh cse544@192.168.122.133
```

## 2. How to assign Attributes
p2 tests are located under `/home/cse544/p2` folder, the attrs are set as below:

* file: foo.txt
security.sample="trusted"

* file: bar.txt
security.sample="untrusted"

* file: user_test
security.sample="trusted"

* file: cwl_test
security.sample="trusted"


```
$ sudo setfattr -n security.sample -v "untrusted" foo.txt
$ sudo setfattr -n security.sample -v "trusted" bar.txt
$ sudo setfattr -n security.sample -v "trusted" user_test
$ sudo setfattr -n security.sample -v "trusted" cwl_test
```
Please try below commands to verify:
```
$ getfattr -d -m security foo.txt
$ getfattr -d -m security bar.txt
$ getfattr -d -m security user_test
$ getfattr -d -m security cwl_test
```
