# COVERTOVERT
Open source implementation of "network" covert channels.

## Installation

Install docker (and optionally compose V2 plugin - not the docker-compose!) and VSCode on your sytstem. Run the docker containers as non-root users.

To start sender and receiver containers:
```
docker compose up -d
```

To stop sender and receiver containers:
```
docker compose down
```

Note that, if you orchestrate your containers using docker compose, the containers will have hostnames ("sender" and "receiver") and DNS will be able to resolve them...

In one terminal, attach to the sender container
```
docker exec -it sender bash
```
In another terminal, attach to the receiver container
```
docker exec -it receiver bash
```

and you will be in your Ubuntu 22.04 Docker instance (python3.10.12 and scapy installed). After running the Ubuntu Docker, you can type "ip addr" or "ifconfig" to see your network configuration (work on eth0).

Docker extension of VSCode will be of great benefit to you.

Note that if you develop code in these Docker instances and you stop the machine, your code will be lost. That is why it is recommended to use Github to store your code and clone in the machine, and push your code to Github before shutting the Docker instances down. The other option is to work in the /app folder in the sender and receiver Docker instances which are mounted to the "code" directory of your own machine.

**IMPORTANT** Note that the "code" folder on your local machine are mounted to the "/app" folder (be careful it is in the root folder) in the sender and receiver Docker instances (read/write mode). You can use these folders (they are the same in fact) to develop your code. Other than the /app folder, this tool does not guarantee any persistent storage: if you exit the Docker instance, all data will be lost.

You can develop your code on your local folders ("code/sender" and "code/receiver") on your own host machine, they will be immediately synchronized with the "/app" folder on containers. The volumes are created in read-write mode, so changes can be made both on the host or on the containers. You can run your code on the containers.

Additionally, the local "examples" folder is mapped to the "/examples" folder in the containers. In that folder, there is a covert timing channel example including sender, receiver and base classes. In the second phase, you will implement a similar system, so it is recommended to look at the example for now.

# Covert Storage Channel that exploits Protocol Field Manipulation using Opcode Flag field in DNS [Code: CSC-PSV-DNS-OCF]

Overview

The covert channel:

    Encrypts and hides binary messages within the DNS Opcode field.
    Sends DNS packets to the target receiver.
    Decrypts the Opcode field on the receiver's side to reconstruct the original message.

    Capacity: 23.51831 bits per second. This is the average sending rate of 10 128-bit packets.

The channel leverages bit-level manipulations to securely encode information into DNS packets while maintaining compliance with protocol structures.
How It Works
Encryption & Decryption

    The binary message is split into 2-bit chunks.
    Each chunk (bit1 and bit2) is encrypted using:
        A 4-bit XOR key.
        A transformation rule (4-bit integer).
    The encrypt function:
        Applies bit-level swaps, reversals, and inversions based on the rule.
        Combines the manipulated bits into a 4-bit value.
        XORs the result with the key for added security.

The decrypt function reverses these operations to retrieve the original 2-bit chunk.
After each encrpytion and decrpytion, rule is incremented by the specified increment value and then taken module 16. This is done for making the decryption process more difficult from outside.

Sending Mechanism

    A random binary message is generated using the generate_random_binary_message_with_logging() function.
    The message is divided into 2-bit chunks.
    Each chunk is encrypted and assigned to the DNS Opcode field.
    The rule is incremented by the specified increment value and then taken modulo 16.
    DNS query packets (using the scapy library) are sent to a target receiver on port 53.

Receiving Mechanism

    The program sniffs DNS packets on port 53.
    For each packet, the Opcode field is decrypted to extract the 2-bit chunks.
    The rule is incremented by the specified increment value and then taken modulo 16.
    The chunks are concatenated into an 8-bit byte stream.
    Each byte is converted into an ASCII character.
    The process continues until the end-of-message marker (".") is received.

Dependencies

    Python 3.x
    Scapy Library for packet manipulation:

    pip install scapy

    Network privileges (e.g., root/admin access) for packet sniffing.

Usage
Sending Messages

Run the send function to generate and send a covert message:

xor_key = 0b1010           # 4-bit XOR key
rule = 0b1101              # 4-bit transformation rule
increment = 0b0011         $ 4-bit increment value
log_file = "sent_log.txt"  # Log file to store the original message

channel = MyCovertChannel()
channel.send(xor_key, rule, increment, log_file)

Receiving Messages

Run the receive function to sniff and decode the covert message:

xor_key = 0b1010           # Must match the sender's XOR key
rule = 0b1101              # Must match the sender's transformation rule
increment = 0b0011         # Must match the sender's increment value
log_file = "received_log.txt"

channel = MyCovertChannel()
channel.receive(xor_key, rule, increment, log_file)

Files

    MyCovertChannel.py: Contains the implementation of the covert DNS channel.
    sent_log.txt: Logs the original message sent by the sender.
    received_log.txt: Logs the message decoded by the receiver.

Example Workflow

    Sender runs the following script:

xor_key = 0b1010
rule = 0b1101
increment = 0b0011
channel = MyCovertChannel()
channel.send(xor_key, rule, increment, "sent_log.txt")

Output:

    A random binary message is generated, encrypted, and sent using DNS packets.

Receiver runs the following script:

    xor_key = 0b1010
    rule = 0b1101
    increment = 0b0011
    channel = MyCovertChannel()
    channel.receive(xor_key, rule, increment, "received_log.txt")

    Output:
        Packets are sniffed, decrypted, and the original message is reconstructed.

    The messages in sent_log.txt and received_log.txt should match.

License

This project is provided for educational purposes only. Use responsibly and ethically