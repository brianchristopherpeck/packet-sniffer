# Packet Sniffer

## Help
```
python packet_sniffer.py --help
```

## Options
```
Options:
  -h, --help            show this help message and exit
  -i, --interface		Network Interface Card to sniff packets on
```

## Example command for MacOSX
```
sudo python packet_sniffer.py  -i en0
```

## Example command for Linux
```
sudo python packet_sniffer.py  -i eth0
```

### Currently does NOT work with Python3

#### ToDo:
1. Upgrade to Python3