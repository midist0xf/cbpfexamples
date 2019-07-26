# cbpfexample

Two C programs to show how to attach a cBPF filter program to a raw socket or to
an udp socket.

cbpfprogs file contains different filters with different level of complexity
that can be used in raw.c.


## USAGE

### raw

```gcc raw.c -o raw ```

```sudo setcap cap_net_raw+ep ./raw ```

```./raw [-i ifname]```

The default interface name is eth0. 

To change filter copy the cbpf assembly from the cbpfprogs file and paste it in the initialization block of ```struct sock_prog bpfcode[]```.

Based on the filter you choose to use you should accordingly uncomment/comment the functions to print the correct headers.

### udp

```gcc udp.c -o udp ```

```./udp ```

To test the filter execute on another terminal 

```nc -p 1030 -u localhost 55555```

and then 

```nc -p 1031 -u localhost 55555```

## EXAMPLE
### raw
![example](https://github.com/midist0xf/cbpfexamples/blob/master/pingheaders.png)
![example](https://github.com/midist0xf/cbpfexamples/blob/master/pinglo.png)
### udp


## FILTERS EXPLANATION
[To do]
