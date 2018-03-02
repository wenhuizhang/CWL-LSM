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
## 3. dmesg logs
After executing `/home/cse544/p2-user/cwl_test` and `/home/cse544/p2-user/user_test /home/cse544/p2-user/foo.txt /home/cse544/p2-user/bar.txt ` 
Please remind the execution order.
```
Mar  1 22:15:44 ubuntu kernel: [ 8948.728027] Sample: Exiting.
Mar  1 22:15:52 ubuntu kernel: [ 8956.213256] Sample:  Initializing.
Mar  1 22:15:52 ubuntu kernel: [ 8956.213280] Sample:  Debugfs created: cwl: 0xffff810071046b60d, cwlite: 0xffff810071046c30d.
Mar  1 22:16:08 ubuntu kernel: [ 8972.979573] sample_bprm_set_security: set task pid=30440 of ssid 0x2
Mar  1 22:16:08 ubuntu kernel: [ 8972.979596] inode_has_perm: target task pid=30440 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/user_test) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.981330] inode_has_perm: target task pid=30440 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/user_test) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.983021] inode_has_perm: target task pid=30440 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/user_test) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.984219] inode_has_perm: target task pid=30440 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:unk?) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.985374] sample: New security setting (0): pid=30440, sec=0x2
Mar  1 22:16:08 ubuntu kernel: [ 8972.986192] inode_has_perm: target task pid=30440 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/foo.txt) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.987206] inode_has_perm: target task pid=30440 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/foo.txt) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.987704] sample: New security setting (1): pid=30440, sec=0x10000002
Mar  1 22:16:08 ubuntu kernel: [ 8972.988058] inode_has_perm: target task pid=30440 of ssid 0x10000002 authorized for inode osid:ops 0x1:0x4 (file:/home/cse544/p2-user/bar.txt) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.988530] sample: New security setting (0): pid=30440, sec=0x2
Mar  1 22:16:08 ubuntu kernel: [ 8972.988951] sample: New security setting (1): pid=30440, sec=0x10000002
Mar  1 22:16:08 ubuntu kernel: [ 8972.989393] inode_has_perm: target task pid=30440 of ssid 0x10000002 authorized for inode osid:ops 0x1:0x4 (file:/home/cse544/p2-user/bar.txt) 
Mar  1 22:16:08 ubuntu kernel: [ 8972.990239] sample: New security setting (0): pid=30440, sec=0x2
Mar  1 22:16:08 ubuntu kernel: [ 8972.990906] inode_has_perm: task pid=30440 of ssid 0x2 NOT authorized (-4) for inode osid 0x1 (file:/home/cse544/p2-user/bar.txt) for ops 0x4
Mar  1 22:16:50 ubuntu kernel: [ 9014.866137] sample_bprm_set_security: set task pid=30442 of ssid 0x2
Mar  1 22:16:50 ubuntu kernel: [ 9014.866156] inode_has_perm: target task pid=30442 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/cwl_test) 
Mar  1 22:16:50 ubuntu kernel: [ 9014.867397] inode_has_perm: target task pid=30442 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/cwl_test) 
Mar  1 22:16:50 ubuntu kernel: [ 9014.867917] inode_has_perm: target task pid=30442 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/cwl_test) 
Mar  1 22:16:50 ubuntu kernel: [ 9014.868533] inode_has_perm: target task pid=30442 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:unk?) 
Mar  1 22:16:50 ubuntu kernel: [ 9014.869955] sample: New security setting (0): pid=30442, sec=0x2
Mar  1 22:16:50 ubuntu kernel: [ 9014.870262] sample: New security setting (1): pid=30442, sec=0x10000002
Mar  1 22:16:50 ubuntu kernel: [ 9014.870555] sample: New security setting (0): pid=30442, sec=0x2
Mar  1 22:17:24 ubuntu kernel: [ 9048.360075] sample_bprm_set_security: set task pid=30448 of ssid 0x2
Mar  1 22:17:24 ubuntu kernel: [ 9048.360095] inode_has_perm: target task pid=30448 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/cwl_test) 
Mar  1 22:17:24 ubuntu kernel: [ 9048.361091] inode_has_perm: target task pid=30448 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/cwl_test) 
Mar  1 22:17:24 ubuntu kernel: [ 9048.361521] inode_has_perm: target task pid=30448 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/cwl_test) 
Mar  1 22:17:24 ubuntu kernel: [ 9048.362118] inode_has_perm: target task pid=30448 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:unk?) 
Mar  1 22:17:24 ubuntu kernel: [ 9048.363202] sample: New security setting (0): pid=30448, sec=0x2
Mar  1 22:17:24 ubuntu kernel: [ 9048.363573] sample: New security setting (1): pid=30448, sec=0x10000002
Mar  1 22:17:24 ubuntu kernel: [ 9048.363876] sample: New security setting (0): pid=30448, sec=0x2
Mar  1 22:17:32 ubuntu kernel: [ 9055.972449] sample_bprm_set_security: set task pid=30449 of ssid 0x2
Mar  1 22:17:32 ubuntu kernel: [ 9055.972461] inode_has_perm: target task pid=30449 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/user_test) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.973672] inode_has_perm: target task pid=30449 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/user_test) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.980946] inode_has_perm: target task pid=30449 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/user_test) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.983144] inode_has_perm: target task pid=30449 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:unk?) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.984563] sample: New security setting (0): pid=30449, sec=0x2
Mar  1 22:17:32 ubuntu kernel: [ 9055.984897] inode_has_perm: target task pid=30449 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/foo.txt) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.985335] inode_has_perm: target task pid=30449 of ssid 0x2 authorized for inode osid:ops 0x2:0x4 (file:/home/cse544/p2-user/foo.txt) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.985784] sample: New security setting (1): pid=30449, sec=0x10000002
Mar  1 22:17:32 ubuntu kernel: [ 9055.986077] inode_has_perm: target task pid=30449 of ssid 0x10000002 authorized for inode osid:ops 0x1:0x4 (file:/home/cse544/p2-user/bar.txt) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.986507] sample: New security setting (0): pid=30449, sec=0x2
Mar  1 22:17:32 ubuntu kernel: [ 9055.986770] sample: New security setting (1): pid=30449, sec=0x10000002
Mar  1 22:17:32 ubuntu kernel: [ 9055.987243] inode_has_perm: target task pid=30449 of ssid 0x10000002 authorized for inode osid:ops 0x1:0x4 (file:/home/cse544/p2-user/bar.txt) 
Mar  1 22:17:32 ubuntu kernel: [ 9055.988110] sample: New security setting (0): pid=30449, sec=0x2
Mar  1 22:17:32 ubuntu kernel: [ 9055.988717] inode_has_perm: task pid=30449 of ssid 0x2 NOT authorized (-4) for inode osid 0x1 (file:/home/cse544/p2-user/bar.txt) for ops 0x4
```
## 4. files logs
```
cse544@ubuntu:/usr/src/linux-2.6.23/security$ /home/cse544/p2-user/cwl_test 
Path: /sys/kernel/debug/cwl/cwlite
open: fd 3
in cwlite_off
Setting CW-Lite OFF
open: after off 0
CWL: fd 3
CWL: before 0
in cwlite_on
Setting CW-Lite ON
CWL: after on 1 cwl is 1
in cwlite_off
Setting CW-Lite OFF
CWL: reset off 0 cwl is 0
close: fd: 3; ret 0
cse544@ubuntu:/usr/src/linux-2.6.23/security$ 
cse544@ubuntu:/usr/src/linux-2.6.23/security$ /home/cse544/p2-user/user_test /home/cse544/p2-user/foo.txt /home/cse544/p2-user/bar.txt 
Path: /sys/kernel/debug/cwl/cwlite
open: fd 3
in cwlite_off
Setting CW-Lite OFF
open: after off 0
user: /home/cse544/p2-user/foo.txt attribute trusted
?
 @
in cwlite_on
Setting CW-Lite ON
in cwlite_off
Setting CW-Lite OFF
user: /home/cse544/p2-user/bar.txt attribute untrusted
in cwlite_on
Setting CW-Lite ON
in cwlite_off
Setting CW-Lite OFF


close: fd: 3; ret 0

```
