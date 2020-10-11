# CRAB

**C**onnection **R**edirect Lo**A**d **B**alancer is a new scheme for L4 load balancing targeting specifically internal cloud workloads.
CRAB was presented at the *ACM Symposium on Cloud Computing 2020* ([SoCC2020](https://acmsocc.github.io/2020/)). You can find the paper [here](https://dl.acm.org/doi/10.1145/3419111.3421304)

## Organisation

This repository holds the code used in the paper evaluation.

- ```middlebox```: holds the implementations of the CRAB load balancer using different technologies
- ```endpoints```: holds the CRAB support for the clients and servers either through a modified kernel or through the use of netfilter modules.

You can find instructions on how to build and run the load balancer and the modified servers and clients in each folder.

To fetch all the dependencies:

<code>
git submodule update --init --recursive
</code>
