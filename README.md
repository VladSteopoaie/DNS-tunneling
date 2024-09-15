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

Did you know that arbitrary data can be transferred using a resolution protocol like DNS? Shocking, right? Not only is this possible, but it also has some interesting utilities, such as exfiltrating data from remote networks or bypassing paywalls when accessing the web.

Imagine you have a PC on a local network (like your home network) and also a remote machine somewhere on the internet that you can reach. Of course, for domain resolution, the router needs access to a DNS server. The setup would look something like this (abstracting away a lot of complexity):

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

This is a Docker Compose project that has the same network layout as [above](#network-layout).
For each container, there is a specific folder and dockerfile (dockerfiles are in the `docker/` folder).

The entire project consists of two DNS server scripts, two DNS tunnel server scripts, and a DNS tunnel client script.

### How does DNS tunneling work

#### The concept
The concept is really simple to understand. There is `LOCAL` that wants to get a file from `REMOTE`, and the process goes like this:
1. `LOCAL` crafts a special DNS packet in which it defines two things (the name of the file and a specific path on which it expects to communicate with the server, a.k.a., a stream).
2. `REMOTE` receives the packet, and it responds (on the same stream) either with an error or with the number of packets that `LOCAL` should expect to complete the transfer.
3. `LOCAL` receives the confirmation, and if there are no errors, it starts asking for packets in order.
4. `REMOTE` receives each request from `LOCAL` and starts inserting data into the packets.
5. The process continues until the transfer is completed.

#### In-depth
Now under the hood, the story is a bit more complex, and some knowledge of DNS and record types is necessary. [Here](https://www.fortinet.com/resources/cyberglossary/what-is-dns) is a read about the DNS protocol, and [here](https://www.cloudflare.com/learning/dns/dns-records/) is one about record types.

##### Establishing connection
To be able to communicate via DNS, there has to be a way for a random DNS server on the internet to redirect your query to a DNS server you own.

To achieve this on the web, you will have to own a domain, for example, `mydomain.top`. You'll also need to have access to a DNS server's records (let's name this server `DENIS`) and define a subdomain for a name server, let's say `ns.mydomain.top`, that can point to your machine, which should have an IP, for example `10.8.8.16`. If everything is right now, your machine can be accessed via IP and via 'ns.mydomain.top', and `DENIS` will keep your name server as such:
```
ns.mydomain.top IN A 10.8.8.16
``` 

Perfect. Now all DNS servers should know how to access your machine since they will ask `DENIS`. Now we have to make `DENIS` redirect the query to the other server (`10.8.8.16` a.k.a. `REMOTE`).

We need a special subdomain for our tunnel, in my case `tunnel.mydomain.top`, and since we want to receive DNS packets, we have to specify a name server that `DENIS` should query in order to reach 'tunnel.mydomain.top', and that should look something like this:
```
tunnel.mydomain.top IN NS ns.mydomain.top
ns.mydomain.top IN A 10.8.8.16
```

Now if we make a query and ask about `tunnel.mydomain.top`, most probably the query will be redirected to `DENIS`. The server will look through it's records and will find that `tunnel.mydomain.top` is managed by `ns.mydomain.top` which is at `10.8.8.16` and it will redirect the query to our server! Not only that, but we can actually type anything in front of the tunnel domain (example: `the.world.is.awesome.tunnel.mydomain.top`) and well receive that query to our server.

##### Designing our own communication protocol

DNS tunneling is not a proper feature of DNS, so we have to think for ourselves when trying to communicate between the client and the server. Since `REMOTE` can now receive any query at any time that ends with `tunnel.mydomain.top` we have to design a way for our server to recognize the origin of the sender so each sender will need an `ID` which I will call `STREAM ID` and to also consider the direction of the stream I will define `UP` for client -> server and `DOWN` for server -> client. A query could look something like this:
```
(data)      .1337         .up       .tunnel.mydomain.top
             ----          --        -------------------
           STREAM ID    DIRECTION          DOMAIN
```

Now let's implement the steps from [the concept](#the-concept):

###### Step 1

`LOCAL` would like to download a file, so in the data section of the query it can specify the file name.

```sh
# requesting text.txt
ORSXQ5BOOR4HI===.1337.up.tunnel.mydomain.top
```

`Note:` The file name is encoded in Base 32 because domain names are case insensitive (Base 32 encoding is case insensitive as well).

###### Step 2

Now `REMOTE` can parse the request and search for the file on the system. The response would be:

```sh
# if an error occurred on the server (most probably the file was not found)
ORSXQ5BOOR4HI===.1337.up.tunnel.mydomain.top IN CNAME 0.1337.down.tunnel.mydomain.top

# if the request was successful
ORSXQ5BOOR4HI===.1337.up.tunnel.mydomain.top IN CNAME 15.1337.down.tunnel.mydomain.top
```

###### Step 3
If there are no errors, `LOCAL` should start asking for packets in order and wait for a response.

```
1.1337.up.tunnel.mydomain.top
```

###### Step 4
`REMOTE` responds with a chunk of data (in my case 400 bytes of Base 64 encoded data, which is 300 bytes of actual data) in a `TXT` record:

```
1.1337.down.tunnel.mydomain.top IN TXT
"AAAAlAgfAAAAgQDKrd3sFmf8aLX6FdU8ThUy3SRWGhotR6EsAavqHgBzH2khqsQHQjEf355jS7cT
G+4a8kAmFVQ4mpEEJeBE6IyDWbAQ9a0rgOKcsaWwJ7GdngGm9jpvReXX7S/2oqAIUFCn0M8="
"MHw9tR0kkDVZB7RCfCOpjfHrir7yuiCbt7FpyX8AAAABBQAAAAAAAAAA"
```

###### Step 5
`Step 3` and `Step 4` repeat until the transfer is completed.

### DNS server

#### Description

A minimal DNS server available in two programming languages, `C++` and `Python`.

The server is capable of:
- local lookups stored in a file (`dns_server/modules/dns_records.txt`)
- online lookups
- recursive lookups

It can manage six types of records (A, NS, CNAME, MX, TXT, AAAA).

`Disclaimer:` The C++ version of the script is my adaptation of a Rust DNS server guide available [here](https://github.com/EmilHernvall/dnsguide/tree/master) (strongly recommended).

#### Setup

To make the server automatically start when deploying the container, you have to modify the `dns_server/setup.sh` script to make sure that one of the following lines is uncommented:

```bash
# bin/dns_server 53 # to start the c++ server
/root/.venv/bin/python dns_server.py 53 # to start the python server
```
By default, the Python server will start at deployment. If you want to switch to the C++ server, uncomment the first line and comment the one that is starting the Python server.

`Note:` there is also a makefile (`dns_server/makefile_server`) if you want to compile the C++ server. Use the command:

```bash
make -f makefile_server # make sure to be in dns_server/ folder
```
Source files: `dns_server/dns_server.cpp`, `dns_server/dns_server.py`

### DNS tunnel server

#### Description

A fake DNS server that can respond to custom-crafted requests when accessed. It is designed to work with the `DNS tunnel client`. It is available in two programming languages: `C++` and `Python`.

The server is capable of:
- processing DNS packets
- search files
- send data via DNS

`Note:` when searching for a file the script will, by default, look in `/etc/tunnel/` directory, so make sure that the file you want to transfer is there.

#### Setup

To make the server automatically start when deploying the container, you need to modify the `remote/setup.sh` script to make sure that one of the following lines is uncommented:

```bash
# bin/dns_tunnel # to start the c++ server
# /root/.venv/bin/python dns_tunnel.py # to start the python server
```
By default, no server will start at deployment, if you want the server to start automatically uncomment the first line (for the c++ server) or the second one (for the Python server).

`Note:` there is also a makefile (`remote/makefile_tunnel`) if you want to compile the C++ tunnel. `Warning`, before trying to compile if you are outside of a container you'll have to copy the `dns_server/modules/` directory to `remote/`. Use the commands:

```bash
# use the next 2 commands only if outside of a container
cp -r dns_server/modules remote/modules
cd remote
make -f makefile_tunnel
```

Source files: `remote/dns_tunnel.cpp`, `remote/dns_tunnel.py`


### DNS tunnel client

#### Description

A script designed to communicate with the `DNS tunnel server` and retrieve a file from the server via DNS. Available only in `Python`.

The script is capable of:
- crafting special DNS request for a specific domain
- createint and managing a (somewhat reliable) stream of communication via UDP
- storing contents received on the machine

`Note:` Files received by the server will be stored in `local/client_data/`

Source files: `local/dns_client.py`

[Get to the top](#dns-tunneling)

## Usage

### Requirements
- [docker](https://docs.docker.com/engine/install/)
- [docker-compose](https://docs.docker.com/compose/install/standalone/)

Clone the repository:
```sh
git clone https://github.com/VladSteopoaie/DNS-tunneling.git
cd DNS-tunneling/
```

Managing the containers (might require administrative privileges):
```sh
# to start the containers
docker-compose up # use `-d` if you want docker to detach

# to drop the containers
docker-compose down

# to start the containers but rebuild the images (if you changed some settings)
docker-compose up --build
```

To connect to one of the containers use:
```sh
docker exec -it <name> /bin/bash
# names available: `dns_server`, `local`, `remote`, `router`
```

By default, there are two files that can be transferred (a text file and an image). You can add more in `remote/data/` folder.

To begin the transfer, we have to connect to `local` and `remote` (only if no server starts automatically) with docker.

`Note:` On every container, the files associated with it are stored in `/scripts/` directory.

On `remote`:
```sh
cd /scripts/
python dns_tunnel.py # for the python server
# or
bin/dns_tunnel # for the c++ server
```

On `local`:
```sh
cd /scripts/
# Usage: python dns_client.py <file_name>
python dns_client.py text.txt
```
You should see the following output:
```
#### LOCAL ####
[~] Starting transfer!
[#] Received packet 1.
[#] Received packet 2.
[#] Received packet 3.
...
[#] Received packet 15.

#### REMOTE ####
[~] Received query: ORSXQ5BOOR4HI===.46573.up.tunnel.mydomain.top.
[#] Packet 1 sent!
[~] Received query: 1.46573.up.tunnel.mydomain.top.
[#] Packet 2 sent!
...
[#] Packet 15 sent!
[#] Handled successfully!
```

Now you should have a file `/scripts/client_data/text.txt` on `local`. You can test the integrity of the file with the following commands:

```sh
# on local
md5sum client_data/text.txt
# on remote
md5sum /etc/tunnel/text.txt
```

If the output hash is the same, the transfer was successfully completed!

[Get to the top](#dns-tunneling)