# DNS-tunneling

## Contents
- [Scenario](#scenario)
    - [Network layout](#network-layout)
- [Project overview](#project-overview)
    - [How does DNS tunneling work](#how-does-dns-tunneling-work)
    - [DNS server](#dns-server)
    - [DNS tunnel server](#dns-tunnel-server)
    - [DNS tunnel client](#dns-tunnel-client)
- [Usage](#usage)

## Scenario

Did you know that through a resolution protocol like DNS arbitrary data could be transfered? Shocking I know. 
Not only is this acctualy possible, but it also has some cool utilities (exfiltrating data from remote networks, bypassing paywalls when accessing the web, etc.).

Imagine you have a PC on a local network (let's say you home network) and you also have a remote machine
some where on the internet where you can reach it. Of course for the domain resolution the router needs to
have access to a DNS server. The setup should look something like this (abstracting away a lot of complexity):

### Network layout
```
                                +------------------+
                                |    DNS SERVER    |
                                |  172.11.180.232  |
                                +------------------+
                                         ||
                                         ||
                              dns_net (172.11.180.0/24)
                                         ||
                                         ||
                                +------------------+
                                |      ROUTER      |
                                | 192.168.100.1    |
                                | 172.11.180.1     |
                                | 10.8.8.1         |
                                +------------------+
                              //                    \\
                             //                      \\
          local_net (192.168.100.0/24)            remote_net (10.8.8.0/24)
                 //                                              \\
                //                                                \\
        +----------------+                                 +-----------------+
        |     LOCAL      |                                 |     REMOTE      |
        | 192.168.100.98 |                                 |    10.8.8.16    |
        +----------------+                                 +-----------------+

```

These are fictional networks and addresses for demonstration purposes.


The goal is to transfer a file from `REMOTE` to `LOCAL` using only the DNS protocol. 

[Get to the top](#dns-tunneling)

## Project overview

This is a docker compose project which has the same network layout as [above](#network-layout).
For each container there is a specific folder and dockerfile (dockerfiles are in `docker/` folder).

The entire project consists of 2 DNS server scripts, 2 DNS tunnel server scripts and a DNS tunnel client script.

### How does DNS tunneling work

#### The concept
The concept is really simple to understand. There is `LOCAL` that wants to get a file from `REMOTE`, and the process goes like this:
1. `LOCAL` crafts a special DNS packet in which it defines 2 things (the name of the file
and a specific path on which it expects to communicate with the server a.k.a. a stream).
2. `REMOTE` receives the packet and it responds (on the same stream) either with an error
or with the number of packets that `LOCAL` should expect to complete the transfer.
3. `LOCAL` receives the the confirmation and if there are no errors it starts asking for packets
in order.
4. `REMOTE` receives each request form `LOCAL` and starts inserting data into the packets.
5. The process continues untill the transfer is completed.

#### In-depth
Now under the hood the story is a bit more complex and some knowledge of DNS and record types is necessary.
[Here](https://www.fortinet.com/resources/cyberglossary/what-is-dns) is a read about the DNS protocol and 
[here](https://www.cloudflare.com/learning/dns/dns-records/) is one bout record types.

##### Establishing connection
To be able to communicate via DNS there has to be a way for a random DNS server on the internet
to redirect your query to a DNS server you own. 

To achieve this on the web you will have to own a domain, for example `mydomain.top`. You'll also need to 
have access to a DNS server's records and define a subdomain for a name server, let's say `ns.mydomain.top`, that can point to your machine 
which should have an IP, for example `10.8.8.16`. If everything is right now your machine can be accessed
via IP and via `ns.mydomain.top` and DNS servers will keep your name server as such:

```
ns.mydomain.top IN A 10.8.8.16
``` 

Perfect now all DNS servers should know how to access your machine, but we need to make them do so.

We need a special subdomain for our tunnel, in my case `tunnel.mydomain.top`, and since we want to receive 
DNS packets we have to specify a name server that the DNS server should query in order to reach `tunnel.mydomain.top`
and that should look somethink like this:

```
tunnel.mydomain.top IN NS ns.mydomain.top
ns.mydomain.top IN A 10.8.8.16
```

Now if we make a query and ask about `tunnel.mydomain.top` most probably the query will be redirected
to the DNS server that holds the records we've just inserted (we don't own this server, we can just insert
records in it). The server will look through it's records and will find that `tunnel.mydomain.top` is managed by
`ns.mydomain.top` which is at `10.8.8.16` and it will redirect the query to our server! Not only that, but we can actually
type anything in front of the tunnel domain (example: `the.world.is.awesome.tunnel.mydomain.top`) and well receive that query to our server.

##### Designing our own communication protocol

### DNS server

#### Description

A minimal DNS server available in 2 programing languages `C++` and `Python`.

The server is capable of:
- local lookups stored in a file (`dns_server/modules/dns_records.txt`)
- online lookups
- recursive lookups

And it can manage 6 types of records (A, NS, CNAME, MX, TXT, AAAA)

`Disclaimer:` The C++ version of the script is an adaptation of a 
Rust DNS server guide available [here](https://github.com/EmilHernvall/dnsguide/tree/master) (strongly recommended). 


#### Setup

To make the server automatically start when deploying the container you have to modify the `dns_server/setup.sh` 
script to make sure that one of the following lines is uncomented:

```bash
# bin/dns_server 53 # to start the c++ server
/root/.venv/bin/python dns_server.py 53 # to start the python server
```
By default the python server will start at deployment, if you want to switch to the C++ server 
uncoment the first line and coment the one that is starting the python server.

Source files: `dns_server/dns_server.cpp`, `dns_server/dns_server.py`

Note: there is also a makefile (`dns_server/makefile_server`) if you want to compile the C++ server.
Use the command:

```bash
make -f makefile_server # make sure to be in dns_server/ folder
```

### DNS tunnel server

#### Description
#### Setup

Source files: `remote/dns_tunnel.cpp`, `remote/dns_tunnel.py`

`Note:` there is also a makefile (`remote/makefile_tunnel`) if you want to compile the C++ tunnel.
`Warning`, before trying to compile if you are outside of a container you'll have to copy the 
`dns_server/modules/` directory to `remote/`.
Use the commands:

```bash
# use the next 2 commands only if outside of a container
cp -r dns_server/modules remote/modules
cd remote
make -f makefile_tunnel
```

[Get to the top](#dns-tunneling)

## Usage
[Get to the top](#dns-tunneling)