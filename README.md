# cbpfexamples

A C program to show how to attach a cBPF filter program to a raw socket.
The code contains different filters with different level of complexity. 


**USAGE**

```gcc cbpfexamples.c -o cbpfexamples ```

```sudo setcap CAP_NET_RAW+ep ./cbpfexamples ```

```./cbpfexamples [-i ifname]```

The default interface name is wlan0. 

Based on the filter you choose to use you should accordingly uncomment/comment the functions to print the correct headers.


**FILTERS EXPLANATION**
