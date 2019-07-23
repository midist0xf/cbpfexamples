# cbpfexample

A C program to show how to attach a cBPF filter program to a raw socket.

cbpfprogs file contains different filters with different level of complexity. 


## USAGE

```gcc cbpfexample.c -o cbpfexample ```

```sudo setcap cap_net_raw+ep ./cbpfexample ```

```./cbpfexample [-i ifname]```

The default interface name is wlan0. 

To change filter copy the cbpf assembly from the cbpfprogs file and paste it in the initialization block of ```struct sock_prog bpfcode[]```.

Based on the filter you choose to use you should accordingly uncomment/comment the functions to print the correct headers.

## EXAMPLE
![example](https://github.com/midist0xf/cbpfexamples/blob/master/pingheaders.png)
![example](https://github.com/midist0xf/cbpfexamples/blob/master/pinglo.png)


## FILTERS EXPLANATION
