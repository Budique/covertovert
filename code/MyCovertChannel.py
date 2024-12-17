from CovertChannelBase import CovertChannelBase
from scapy.all import DNS, DNSQR,DNSRR, IP, UDP, sniff

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
    def encrypt(self,bit1, bit2, xor_key, rule):

        binary_list = [int(bit) for bit in f"{rule:04b}"]
        leftmost = ((1 - bit1) << 1) + bit1  #0b0 maps to 0b10,0b1 maps to 0b01
        rightmost = ((1 - bit2) << 1) + bit2 

        if binary_list[0] == 1:  #0b0 maps to 0b01,0b1 maps to 0b10
            leftmost = (bit1 << 1) + (1 - bit1)
        if binary_list[1] == 1:  #0b0 maps to 0b01,0b1 maps to 0b10
            rightmost = (bit2 << 1) + (1 - bit2)

        # Combine leftmost and rightmost into a 4-bit result
        tmpresult = (leftmost << 2) + rightmost

        if binary_list[2] == 1:  # if swap bit is set Swap the leftmost and rightmost bits
            tmpresult = (rightmost << 2) + leftmost

        if binary_list[3] == 1:  # if reverse bit set reverse the binary representation
            binary_str = bin(tmpresult)[2:].zfill(4)  # Ensure 4-bit length
            reversed_binary_str = binary_str[::-1]
            tmpresult = int(reversed_binary_str, 2)  # Convert back to integer

        return tmpresult ^ xor_key  # xor with the specified  key


    def decrypt(self,encrypted_value, xor_key, rule):
        tmpresult = encrypted_value ^ xor_key  # Reverse XOR step

        binary_list = [int(bit) for bit in f"{rule:04b}"]

        if binary_list[3] == 1:  # if its reversed,reverse the binary representation
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


    def send(self, xor_key, rule,log_file_name):
        """
        - In this function, a random binary message is generated using the `generate_random_binary_message_with_logging` function from the `CovertChannelBase` class.
        - The binary message is divided into chunks of 2 bits each (to be encoded into DNS opcode fields).
        - For each 2-bit chunk, the bits (bit1 and bit2) are encrypted using the `encrypt` function, which applies transformations based on the provided `xor_key` and `rule`. they are both 4 bit integers (0-15)
        - The encrypted value is assigned to the DNS opcode field in a DNS query packet.
        - The DNS query packet is then sent to the receiver using the `super().send` method, where:
            - Destination IP is set to "receiver".
            - Destination port is set to 53 (standard DNS port).
            - DNS query name is set to "azd.com" (a placeholder domain name).
        - This process continues until all the chunks of the binary message are sent.
        - The sent message is logged to the specified log file for reference.
        """


        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        chunks =[binary_message[i:i+2] for i in range(0, len(binary_message), 2)]
        
        for chunk in chunks:
            bit1 = int(chunk[0],2)
            bit2 = int(chunk[1],2)
            opcode_value = self.encrypt(bit1,bit2,xor_key,rule)


            dns_query = IP(dst="receiver") / UDP(dport=53) / DNS(
                id=1, qd=DNSQR(qname="azd.com"), opcode=opcode_value
            )


            super().send(dns_query)

        
    def receive(self,xor_key, rule, log_file_name):
        """
        - In this function, DNS packets are captured and processed to extract the hidden message.
        - Packet sniffing is performed using the `sniff` function, with a filter to capture UDP packets on port 53 (DNS traffic).
        - For each captured DNS packet:
            - The opcode field of the DNS packet is decrypted using the `decrypt` function, which reverses the encryption process with the specified `xor_key` and `rule`.
            - The decrypted bits (bit1 and bit2) are concatenated to reconstruct the binary message.
        - The binary message is processed in 8-bit chunks, where each 8-bit chunk is converted into its corresponding ASCII character.
        - The characters are accumulated into the final decoded message.
        - The sniffing process stops when a '.' (dot) character is received, indicating the end of the message.
        - The final decoded message is logged to the specified log file for reference.
        """

        binary = ""  # Store the unprocessed message in binary
        message = ""  # Final decoded message
        cur = 0       # Counter to track bits received
        dotAcquired =False

        def stop_sniffing(packet):
            #continue as long as dot is not received
            nonlocal dotAcquired
            return dotAcquired
            

        def process_packet(packet):
            """Processes a single packet, decrypts it, and updates the message."""
            nonlocal binary, message, cur,dotAcquired
            if DNS in packet and hasattr(packet[DNS], 'opcode'):
                dns_packet = packet[DNS]
                opcode_value = dns_packet.opcode
                
                # Decrypt the opcode to retrieve the original bits
                bit1, bit2 = self.decrypt(opcode_value, xor_key, rule)
                chunk = f"{bit1}{bit2}"
                binary += chunk
                cur += 2

                # Process full 8-bit chunks
                while cur >= 8:
                    cur -=8
                    byte = binary[:8]  # Extract first 8 bits
                    character = chr(int(byte, 2))
                    message += character
                    print(f"Received character: {character}")
                    binary = binary[8:]  # Remove processed bits
                    if character == '.':
                        dotAcquired =True
        # Start sniffing with a stop_filter
        sniff(filter="udp port 53", prn=process_packet, stop_filter=stop_sniffing)
                                            
        self.log_message(message, log_file_name)
