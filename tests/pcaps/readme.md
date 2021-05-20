At first we've considered making PCAPs automatically but that proved to be somewhat problematic - most test runners don't have a TPM. We could use virtual TPM, but that would add further another dependency to the test stack. So we've decided to do the PCAPs manually.

### Tshark

It has few nice arguments: 

```
tshark -f "port 6666" -w "tshark1.pcap" --autostop duration:15
```

### Scenarios

- server only
- server + client registration
- server + client login
- server + client login + msg
- server + client polling
- server + multiple clients polling


### Windows 

```
c:\Program Files\Wireshark\
tshark.exe --list-interfaces
tshark.exe -i \Device\NPF_Loopback -f "port 6666" -w "/tmp/pv204/pcap/tshark1.pcap" --autostop duration:15
```
