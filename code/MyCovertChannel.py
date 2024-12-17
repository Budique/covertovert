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
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """

        binary_message = self.generate_random_binary_message_with_logging(log_file_name,20,20)

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
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
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
