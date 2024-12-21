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