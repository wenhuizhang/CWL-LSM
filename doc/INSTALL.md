# Install
```
$ tar -zxvf linux-2.6.23.tar.gz
$ sudo tar -zxvf linux-2.6.23.tar.gz -C /usr/src/
$ cd /usr/src/linux-2.6.23
$ sudo make menuconfig
$ sudo make -j4
$ sudo make modules
$ sudo make modules_install
$ sudo make install
$ sudo update-initramfs -u -k 2.6.23
```


