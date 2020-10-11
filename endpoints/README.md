# CRAB Endpoints

CRAB requires modifications to the TCP stacks of servers and clients. We provide two ways to do so:

- ```linux-4.19.114-mods``` includes a patch to the 4.19.114 kernel that implements support for CRAB. To use that you should download, patch, and build the 4.14.114 Linux kernel.
- ```netfilter-client``` and ```netfilter-server``` extend the currently running kernel through Netfilter modules, thus avoiding the need for building a new kernel.

## CRAB support with Netfilter

### Client
This netfilter module runs in functionality in the context of a  ```PRE_ROUTING``` hook. It intercepts ```SYN-ACK``` packets and if they carry the Connection Redirect option it update the connection state.

To build and insert the module:

```
cd client-netfilter
make
sudo insmod lbbpc_main
```

### Server
The server netfilter module does not implement exactly the same functionality as the modified Linux kernel. Instead of echoing back the Connection Redirect option only for as part of ```SYN-ACK```s whose corresponding ```SYN``` included this option, it inserts the Connection Redirect option to all outgoing ```SYN-ACK``` packets targetting a specifc subnet and port.

To build and insert the module:


```
cd server-netfilter
make
sudo insmod lbbps_main
```

To configure the module:

```
./cfg_lbbs vip port net_mask # e.g. sudo ./cfg_lbbps 10.90.44.217 8080 0xFFFFFFF0
```
