# CRAB Load Balancer

We implemented a CRAB load balancer using different technologies: dpdk, eBPF, netfilter modules, and p4, corresponding to the equivalent folders.

## DPDK
To build the CRAB DPDK load balancer and the vanilla L4 load balancer with DSR used as a base line:

```
cd dpdk
make -C r2p2 dpdk && make
```

Those two load balancers use the R2P2 networking stack. You can find instructions on how to configure the stack [here](https://github.com/epfl-dcsl/r2p2). Make sure to configure the ```/etc/r2p2.conf``` with the equivalent MAC to IP entries.

To run the load balancers

```
sudo ./lbl4-vanilla -l 0 -- ip1,ip2,ip3... # for the vanilla L4 LB with DSR
sudo ./crab -l 0 -- ip1,ip2,ip3...         # for CRAB
```

## eBPF

First you need to install some dependencies:

```
sudo apt-get install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential m4
```

To build the CRAB eBPF load balancer:

```
cd ebpf
make
```

To load the eBPF module:

```
mount -t bpf bpf /sys/fs/bpf/ # mount the bpf fs for pinned maps
sudo sysctl net.core.bpf_jit_enable=1 # enable JIT
sudo ./helpers/xdp_loader --dev DEVICE\_NAME --filename lb/lb_kern.o --native-mode
```

To configure the eBPF module:

```
sudo ./helpers/lb_cfg --dev DEVICE\_NAME --targets ip1@mac1,ip2@mac2
```


## Netfilter
To build and insert the netfilter module

```
cd netfilter && make
sudo insmod lbbpl_main.ko
```

The netfilter module can be configured throught the ```lb_cfg``` program

```
sudo  ./cfg_lbblp &#60;vip&#62; &#60;port&#62; &#60;taget_count&#62; &#60;comma separated target IPs&#62; &#60;LB_RR|LB_RAND&#62;
```

Make sure you enable IP forwarding and allow it in iptables before running the Netfilter CRAB load balancer.

```
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -P FORWARD ACCEPT
```

## P4
If you have questions on running the P4 CRAB load balancer on Tofino please contact marioskogias@gmail.com
