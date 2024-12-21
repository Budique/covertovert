from CovertChannelBase import CovertChannelBase
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sniff
import time # For measuring bitrate/sec

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass

    def encrypt(self, bit1, bit2, xor_key, rule):
        """
        Encrypts a pair of binary bits (`bit1` and `bit2`) into a 4-bit integer using a series of transformations and an XOR operation.

        :param bit1: The first bit (0 or 1) of the pair to be encrypted.
        :type bit1: int
        :param bit2: The second bit (0 or 1) of the pair to be encrypted.
        :type bit2: int
        :param xor_key: A 4-bit integer (0–15) used as the XOR key for encryption.
        :type xor_key: int
        :param rule: A 4-bit integer (0–15) defining the transformations to apply during encryption. Each bit of the rule determines a specific transformation:
            
            - **Rule bit 0**: Modifies `bit1` such that `0` becomes `01` and `1` becomes `10`.
            - **Rule bit 1**: Modifies `bit2` such that `0` becomes `01` and `1` becomes `10`.
            - **Rule bit 2**: If set, swaps the positions of the transformed bits.
            - **Rule bit 3**: If set, reverses the binary representation of the combined result.

        :type rule: int
        :return: The final 4-bit encrypted value.
        :rtype: int
        """

        binary_list = [int(bit) for bit in f"{rule:04b}"]
        leftmost = ((1 - bit1) << 1) + bit1  #0b0 maps to 0b10, 0b1 maps to 0b01
        rightmost = ((1 - bit2) << 1) + bit2 

        if binary_list[0] == 1:  #0b0 maps to 0b01, 0b1 maps to 0b10
            leftmost = (bit1 << 1) + (1 - bit1)
        if binary_list[1] == 1:  #0b0 maps to 0b01, 0b1 maps to 0b10
            rightmost = (bit2 << 1) + (1 - bit2)

        # Combine leftmost and rightmost into a 4-bit result
        tmpresult = (leftmost << 2) + rightmost

        if binary_list[2] == 1:  # if swap bit is set Swap the leftmost and rightmost bits
            tmpresult = (rightmost << 2) + leftmost

        if binary_list[3] == 1:  # if reverse bit set reverse the binary representation
            binary_str = bin(tmpresult)[2:].zfill(4)  # Ensure 4-bit length
            reversed_binary_str = binary_str[::-1]
            tmpresult = int(reversed_binary_str, 2)  # Convert back to integer

        return tmpresult ^ xor_key  # xor with the specified key


    def decrypt(self, encrypted_value, xor_key, rule):
        """
        Decrypts an encrypted 4-bit integer (`encrypted_value`) to retrieve the original binary bits (`bit1` and `bit2`).

        :param encrypted_value: The 4-bit integer resulting from the encryption process.
        :type encrypted_value: int
        :param xor_key: The same 4-bit integer (0–15) used during encryption.
        :type xor_key: int
        :param rule: A 4-bit integer (0–15) specifying the transformations applied during encryption, which are reversed here.
            The rule is interpreted as follows:

            - **Rule bit 0**: If set, reverses the transformation applied to `bit1`.
            - **Rule bit 1**: If set, reverses the transformation applied to `bit2`.
            - **Rule bit 2**: If set, undoes the swapping of transformed bits.
            - **Rule bit 3**: If set, undoes the reversal of the binary representation.

        :type rule: int
        :return: A tuple containing the original first bit (`bit1`) and second bit (`bit2`).
        :rtype: tuple[int, int]
        """
        tmpresult = encrypted_value ^ xor_key  # Reverse XOR step

        binary_list = [int(bit) for bit in f"{rule:04b}"]

        if binary_list[3] == 1:  # if its reversed, reverse the binary representation
            binary_str = bin(tmpresult)[2:].zfill(4)
            reversed_binary_str = binary_str[::-1]
            tmpresult = int(reversed_binary_str, 2)

        # Extract leftmost and rightmost 2 bits
        leftmost = (tmpresult >> 2) & 0b11  # Extract leftmost 2 bits
        rightmost = tmpresult & 0b11       # Extract rightmost 2 bits

        if binary_list[2] == 1:  # if its swapt before swap leftmost and rightmost back
            leftmost, rightmost = rightmost, leftmost

        # Reverse conditional modifications applied during encryption
        if binary_list[0] == 1:
            bit1 = leftmost >> 1
        else:
            bit1 = leftmost & 0b1 # Reverse inversion logic for bit1

        if binary_list[1] == 1:
            bit2 = rightmost >> 1
        else:
            bit2 = rightmost & 0b1  # Reverse inversion logic for bit2

        return bit1, bit2  # Return original bit1 and bit2


    def send(self, xor_key, rule, increment, log_file_name):
        """
        Sends a covert message using DNS query packets by encrypting binary data into the `opcode` field.

        :param xor_key: A 4-bit integer (0–15) used as the XOR key for encryption.
        :type xor_key: int
        :param rule: A 4-bit integer (0–15) defining the initial encryption rule.
        :type rule: int
        :param increment: The increment value for the rule, used to vary the encryption rule for each packet.
        :type increment: int
        :param log_file_name: The name of the file where the sent binary message will be logged.
        :type log_file_name: str

        **Process:**

        - Generates a random binary message using `generate_random_binary_message_with_logging`.

        - Divides the message into chunks of 2 bits, which are encrypted using the `encrypt` function.

        - The encrypted value is assigned to the DNS `opcode` field in a query packet.

        - Sends the DNS query packets to the receiver, with the destination IP set to `"receiver"`, port 53 and a placeholder domain name `"azd.com"`.
        
        - Logs the sent message to the specified log file.

        **Encryption Details:**

        - The `xor_key` and `rule` are used to encrypt each 2-bit chunk.

        - The `rule` is incremented by the `increment` value after processing each chunk and modulo 16 ensures it stays within the 0–15 range.

        :return: None
        """


        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        # For bitrate measurement
        #binary_message = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)

        chunks = [binary_message[i:i+2] for i in range(0, len(binary_message), 2)]
        
        #start_time = time.time()
        
        for chunk in chunks:
            bit1 = int(chunk[0], 2)
            bit2 = int(chunk[1], 2)
            opcode_value = self.encrypt(bit1, bit2, xor_key, rule)

            rule = (rule+increment)%16

            dns_query = IP(dst="receiver") / UDP(dport=53) / DNS(
                id=1, qd=DNSQR(qname="azd.com"), opcode=opcode_value
            )


            super().send(dns_query)
        
        #end_time = time.time()
        #execution_time = end_time - start_time
        #print(f"Sent 128 bits in {execution_time}.\nBitrate: {(128/execution_time):.4f}")

        
    def receive(self, xor_key, rule, increment, log_file_name):
        """
        Receives a covert message by decrypting binary data from DNS query packets captured on port 53.

        :param xor_key: A 4-bit integer (0–15) used as the XOR key for decryption.
        :type xor_key: int
        :param rule: A 4-bit integer (0–15) defining the initial decryption rule.
        :type rule: int
        :param increment: The increment value for the rule, used to vary the decryption rule for each packet.
        :type increment: int
        :param log_file_name: The name of the file where the decoded message will be logged.
        :type log_file_name: str

        **Process:**

        - Captures DNS packets using `sniff`, filtering UDP traffic on port 53.

        - For each packet, decrypts the `opcode` field using the `decrypt` function.

        - The decrypted bits are concatenated to reconstruct the original binary message.

        - Processes the binary data in 8-bit chunks, converting each chunk into its corresponding ASCII character.

        - Stops capturing packets when a '.' (dot) character is received, signaling the end of the message.

        - Logs the final decoded message to the specified log file.


        **Decryption Details:**

        - The `xor_key` and `rule` are used to decrypt each 4-bit `opcode` value.

        - The `rule` is incremented by the `increment` value after processing each packet and modulo 16 ensures it stays within the 0–15 range.

        **Sniffing Details:**

        - Captures only packets from the sender's IP address (`172.18.0.2`) and UDP port 53.
        
        - Stops when a '.' (dot) character is detected in the message.

        :return: None
        """

        binary = ""  # Store the unprocessed message in binary
        message = ""  # Final decoded message
        cur = 0       # Counter to track bits received
        dotAcquired = False
        sender_ip = "172.18.0.2"

        def stop_sniffing(packet):
            #continue as long as dot is not received
            nonlocal dotAcquired
            return dotAcquired
            

        def process_packet(packet):
            """Processes a single packet, decrypts it and updates the message."""
            nonlocal binary, message, cur, dotAcquired, rule, sender_ip
            if IP in packet and sender_ip == packet[IP].src and DNS in packet and hasattr(packet[DNS], 'opcode'):

                dns_packet = packet[DNS]
                opcode_value = dns_packet.opcode
                
                # Decrypt the opcode to retrieve the original bits
                bit1, bit2 = self.decrypt(opcode_value, xor_key, rule)
                rule = (rule+increment)%16

                chunk = f"{bit1}{bit2}"
                binary += chunk
                cur += 2

                # Process full 8-bit chunks
                while cur >= 8:
                    cur -=8
                    byte = binary[:8]  # Extract first 8 bits
                    character = chr(int(byte, 2))
                    message += character
                    #print(f"Received character: {character}")
                    binary = binary[8:]  # Remove processed bits
                    if character == '.':
                        dotAcquired =True
        # Start sniffing with a stop_filter
        sniff(filter="udp port 53", prn=process_packet, stop_filter=stop_sniffing)
                                            
        self.log_message(message, log_file_name)
