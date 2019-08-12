# cbpfexamples
## PACKET FILTERING

Two C programs to show how to attach a cBPF filter program to a raw socket or to
an udp socket.

cbpfprogs.txt file contains different filters with different level of complexity
that can be used in raw.c.


### USAGE

#### raw

```gcc raw.c -o raw ```

```sudo setcap cap_net_raw+ep ./raw ```

```./raw [-i ifname]```

The default interface name is eth0. 

To change filter copy the cbpf assembly from the cbpfprogs.txt file and paste it in the initialization block of ```struct sock_prog bpfcode[]```.

Based on the filter you choose to use you should accordingly uncomment/comment the functions to print the correct headers.

#### udp

```gcc udp.c -o udp ```

```./udp ```

To test the filter execute on another terminal 

```nc -p 1030 -u localhost 55555```

and then 

```nc -p 1031 -u localhost 55555```

### EXAMPLE
#### raw
![example](https://github.com/midist0xf/cbpfexamples/blob/master/packetfiltering/pingheaders.png)
![example](https://github.com/midist0xf/cbpfexamples/blob/master/packetfiltering/pinglo.png)
#### udp
![example](https://github.com/midist0xf/cbpfexamples/blob/master/packetfiltering/udpnc.png)
![example](https://github.com/midist0xf/cbpfexamples/blob/master/packetfiltering/udp.png)

### FILTERS EXPLANATION
[To do]

## SECCOMP
C programs to show seccomp mode 1 (strict), seccomp mode 2 (filter) and libseccomp usage.

### PREREQUISITES
#### libseccomp
Download the tarball from https://github.com/seccomp/libseccomp/releases
```
# ./configure
# make [V=0|1]
# make install
```
### USAGE
#### strictexlib.c
```
gcc -o strictexlib strictexlib.c -lseccomp
./strictexlib
```
#### strict.c strictdup.c strictdupmacro.c
```
gcc -o strict strict.c
./strict
gcc -o strictdup strictdup.c
./strictdup
gcc -o strictdupmacro strictdupmacro.c
./strictdupmacro
```
### EXAMPLE
#### strictexlib
![example](https://github.com/midist0xf/cbpfexamples/blob/master/seccomp/libexportpfc.png)
#### strictdup
![example](https://github.com/midist0xf/cbpfexamples/blob/master/seccomp/stracestrictdup.png)
