# Instructions of Lab


CSE544 - Project #2 - CW-Lite LSM Module
Due Date: Th March 1, 2018 at 11:59pm.

In this assignment, you will complete a Linux Security Module that implements CW-Lite integrity over file operations.

Follow these instructions:

Get the module code from here. This code contains three files: (1) sample.c, which contains an incomplete Linux Security Module that includes stubs for a set of authorization hooks (place in directory linux-2.6.23/security) and (2) Makefile, which enables sample.c to be compiled for the kernel (place in linux-2.6.23/security); and (3) p2-user.tgz, which contains user-space code to test your LSM implementation.

The first major task is to compile your Linux kernel (version 2.6.23) in your experimental environment, so that you can develop and test your sample LSM. Instructions for this task follow:

You will be assigned a VM for this purpose. Instructions for accessing and using the VM are here. I will send you information on your VM and its password(s) separately.

After logging into your VM, you must first configure and build a modified Linux kernel to run in the VM. For more information on kernel building see here. We do have a few modifications, so follow the remaining instructions to configure and build the kernel carefully.

To configure the kernel run make menuconfig. You need to change the configuration options slightly from the defaults. Under security options only select "Enable different security models" and "Socket and Networking Security Hooks" (as "built-in" or "*"). Save your kernel configuration. Verify that the file .config in the root source directory (should be linux-2.6.23) has been modified.

After doing update-grub in the kernel build process, the grub file is not always correct. Make sure that the default line has a value of "0". Also, the first boot entry should look like:

title Ubuntu 7.10, kernel 2.6.23 Default

root (hd0,0)

kernel /boot/vmlinuz root=UUID=a0337087-2abd-481f-938d-980564bf663f ro quiet splash

initrd /boot/initrd.img-2.6.23

quiet

If you cannot boot your VM, you will need to edit files in your VM's filesystem from the host (hecto.cse.psu.edu). To do that you can use guestfish.

sudo guestfish --rw -a /home/cse544_##/cse544_##.qcow2 -i edit /boot/grub/menu.lst

where ## is your VM number.

If you make modifications to linux-2.6.23/security/sample.c for your LSM (which you should), you will need to rebuild the module using the provided Makefile for security directory. Since you have already built the kernel, you can simply recompile the kernel (CONCURRECY=4 make all) and only the file sample.c will be compiled.

Run the module by loading using sudo insmod sample.ko from the security directory. Unload the module with sudo rmmod sample. Check that the module is loaded via lsmod | grep sample.

The goal of this project is to add code to the selected LSM authorization hooks (see the variable sample_ops in sample.c) as necessary to enforce CW-Lite integrity (see the CWLite paper) over file operations. Your project tasks are highlighted by the phrase "YOUR CODE" in the sample.c file. In general, the LSM implementation must perform the following two tasks:

Set CW-Lite Filtering: Implement a debugfs file to enable a program to tell the LSM when it can securely filter an operation that accesses low integrity data, which we call the cwlite flag.

Enforce CW-Lite Authorization: Implement authorization code to use the cwlite flag to authorize access. Only when the flag is on for a process is the process allowed to perform an operation on a low integrity file.

Background: To build your LSM, you will need to know the following background.

We need to assign labels to kernel objects that we authorize (processes and inodes). We label kernel objects based on the label assigned to the files used to create them. Using the filesystem's extended attributes, we store label strings "trusted" and "untrusted" in the file's security.sample attribute. Use the setfattr shell command to label files. See its man page.

Authorization decisions are made based on the labels of the process and inode and the operations requested by the process. For CW-Lite, we define three label values (#defines in sample.c): SAMPLE_UNTRUSTED for low integrity and SAMPLE_TRUSTED for high integrity and SAMPLE_IGNORE for processes that are outside our LSM's control - so we can ignore all processes except those under test. The idea is that a SAMPLE_TRUSTED process should only perform operations on SAMPLE_TRUSTED files unless it has asserted the ability to filter them securely by turning the cwlite flag on, as described below. Only then can it access SAMPLE_UNTRUSTED files. Processes labeled SAMPLE_IGNORE need not be authorized.

Operations are defined in sample.c as well (#defines starting with MAY_). Operations have the expected semantics.

To Set CW-Lite Filtering: Your LSM must create a file in the debugfs filesystem, which is located at /sys/kernel/debug/ on your VM for processes to tell the kernel their CW-Lite state.

To create a debugfs file in a kernel module see the Debugfs Guidance. You will add code to sample.c to implement these actions (create the debugfs filesystem and implement file operations). You need to create a debugfs file that supports the operations performed from user space by the cwlite.h code, which turns CW-Lite filtering on and off in the kernel. Each operation writes one-byte string (2 bytes with null termination) to the debugfs file. Please perform the following steps:

Please create a directory under debugfs called cwl with a single file called cwlite, such that you can read and write the CW-Lite value for your own process (current in the kernel).

When you write to cwlite the aim is to store whether the kernel should allow the process to filter low integrity inputs as part of the process's security label. For each Linux task, a field current->security stores the label (either SAMPLE_UNTRUSTED, SAMPLE_TRUSTED, or SAMPLE_IGNORE, as defined in sample.c). Choose a filter bit in the label. I used the 31st bit - highest in a (u32) representation to encode the CW-Lite status. The idea is if the process is allowed to filter low integrity inputs then the bit is 1, otherwise it is 0.

You will need to program the read and write operations for the cwlite debugfs file to set this bit ON or OFF (on write) and to return the value of bit (on read) through the cwlite.h API. Note that I also provide functions to open and close the CW-Lite file in cwlite.c and a test program to demonstrate its use test.c. One thing I will test is whether this test program works as expected.

To Enforce CW-Lite: Students must complete the code to assign labels to running processes and implement the authorization hooks to enable enforcement of CW-Lite policies. The tasks to be performed are listed below:

The label of a process must be set in the function sample_bprm_set_security to the label of the file being executed. Helper functions are provided in sample.c to extract a file's label from its extended attributes. The label of an file inode being accessed (open, read, write) must be set before authorizing each operation. The label of a newly created file must be set in the function sample_inode_init_security.

Students must modify the authorization decision function has_perm to enforce CW-Lite semantics as defined in the CW-Lite paper for the specific labels and operations. Some of the authorization hooks use helper functions. The inode_has_perm function is a helper function that authorizes file and inode access.

Students must implement small parts of some of the LSM authorization hook functions that are invoked to authorize operations. The list of LSM hooks included in sample.c is listed below (not all require changes).

sample_inode_permission: mediates file open operations (on the file inode)

sample_bprm_set_security: mediates loading of a file into a process (e.g., on exec), labeling the new process as described above

sample_inode_init_security: mediates initialization of a new inode object, setting the label to that of the creating process

sample_inode_setxattr: mediates modification of the extended attributes of a file's inode

sample_inode_create: mediates the return of a newly created file to the process

sample_file_permission: mediates operations on a file descriptor (read, write, append)

NOTE: Not all hooks may require additional code. Use the SELinux versions of the code (linux-2.6.23/security/selinux/hooks.c) for more information on what may be done.

I will assign some test programs to run in the future.

A log of the session will be captured in /var/log/messages. The statements identify the files that were authorized and not authorized by has_perm.

NOTE: Currently, the sample LSM only logs authorization decisions, but does not actually block operations. An LSM authorization hook will block an operation if it returns any value other than 0. Be careful that you either return 0 or only block operations you intend to. Otherwise, other processes will stop working (you have the power, so be careful!).

Please submit your sample.c and your log of the run on the test programs. Also, please submit a list of all the files you had to mark as SAMPLE_TRUSTED to run the test programs on your VM. I will also need information to run your LSM in your VM to test it (e.g., if you changed the password).

When you have completed your module, submit it, the output, and the file labeling, and information necessary to access your VM via Canvas by 11:59pm on Th March 1, 2018. Make sure that you have tested your submission prior to uploading. I will test on your VM.

You are to complete this on your own. Any sharing of code or help during the coding of this project is expressly forbidden. Do not discuss this project with anyone.

Trent Jaeger
