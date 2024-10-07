from scapy.all import sniff
import sys
from prettytable import PrettyTable

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")

# Convert the passed in hex value into an IP address
def convert_hex_to_ip_address(hex):
    dotted_str_representation = ""
    max_len = len(hex)
    for i in range(0, max_len, 2):
        first_hex_char = int(hex[i], 16)*16
        second_hex_char = int(hex[i+1], 16)
        final_num = first_hex_char+second_hex_char
        dotted_str = str(final_num)
        if(i != (max_len-2)):
            dotted_str += "."
        
        dotted_str_representation += dotted_str
    return dotted_str_representation
# Convert the passed in hex value into its colon notation(MAC address) 
def convert_hex_to_colon_notation(hex):
    colon_str_representation = ""
    max_len = len(hex)
    for i in range(0, max_len, 2):
        two_hex_chars = hex[i] + hex[i+1]
        if(i != (max_len-2)):
            two_hex_chars += ":"
        colon_str_representation += two_hex_chars
    return colon_str_representation

# Convert the passed in hex value into its decimal representation may further translated to IP address of MAC address for certain fields
def convert_hex_field_to_Decimal(label, value):
    if "IP Address" in label or label == "Source Protocol Address" or label == "Target Protocol Address":
        decimal_rep_of_hex = convert_hex_to_ip_address(value)
    elif label == "Source Hardware Address" or label == "Target Hardware Address":
        decimal_rep_of_hex = convert_hex_to_colon_notation(value)
    else:
        decimal_rep_of_hex = int(value, 16)
    
    if len(str(decimal_rep_of_hex)) > 17:
        decimal_rep_of_hex = allign_field(decimal_rep_of_hex)
    return decimal_rep_of_hex

# Convert the passed in hex value into its binary representation. This is only done for specific fields otehrwiase this is blank(-)
def convert_hex_field_to_Binary(label, value):
    binary_rep_of_hex = "-"
    if "Flags" in label or "Fragment offset" in label:
        decimal_rep_of_hex = int(value, 16)
        binary_rep_of_dec = bin(decimal_rep_of_hex)
        remove_formatting_binary_rep = binary_rep_of_dec[2:]
        binary_rep_of_hex = remove_formatting_binary_rep
        if len(str(binary_rep_of_hex)) > 17:
            binary_rep_of_hex = allign_field(binary_rep_of_hex)
    return binary_rep_of_hex    

# Allign fields that have values that are too large by showing 10 characters in a row (This is to prevent the table from getting misaligned)
def allign_field(field_value):
    str_field_rep = str(field_value)
    alligned_field_rep = ""
    if len(str_field_rep) > 10:
        i = 1
        for char in list(str_field_rep):
            alligned_field_rep += char
            if i % 10 == 0:
                alligned_field_rep += "\n"
            i+=1

        return alligned_field_rep    

# Create a table where each row is a field with the value and its different representations
def create_table(fields):
    field_table = PrettyTable()
    field_table.field_names = ["Field Name", "Hex", "Decimal", "Binary"]
    for label, value in fields:
        decimal_rep = convert_hex_field_to_Decimal(label, value)
        binary_rep = convert_hex_field_to_Binary(label, value)
        if len(str(value)) > 17:
            alligned__hex = allign_field(value)
            value = alligned__hex
        field_table.add_row([label, value, decimal_rep, binary_rep])
    return field_table

# Parse a TCP hex dump to get the necessary fields and then print out a table showing each fields and the corresponding value
def parse_TCP(hex_data):
    print("TCP hex dump: " + hex_data)
    fields = []
    fields.append(("Source Port", hex_data[0:4]))
    fields.append(("Destination Port", hex_data[4:8]))
    fields.append(("Sequence Number", hex_data[8:16]))
    fields.append(("Acknowledgement Number", hex_data[16:24]))
    fields.append(("Header Length", hex_data[24]))
    fields.append(("Reserved", hex_data[25]))
    fields.append(("Flags", hex_data[26:28]))
    fields.append(("Window Size", hex_data[28:32]))
    fields.append(("Checksum", hex_data[32:36]))
    fields.append(("Urgent Pointer", hex_data[36:40]))
    header_length_decimal = convert_hex_field_to_Decimal("header length", hex_data[24])
    if header_length_decimal > 5:
        num_of_diff_bytes = int(hex_data[24], 16) - 5
        num_of_chars = num_of_diff_bytes * 8
        ending_index = 40 + num_of_chars
        fields.append(("Options", hex_data[40:ending_index]))
        if hex_data[ending_index:]:
            fields.append(("Data", hex_data[ending_index:]))
    print("TCP Table:")
    tcp_table = create_table(fields)
    print(tcp_table)

# Parse a UDP hex dump to get the necessary fields and then print out a table showing each fields and the corresponding value
def parse_UDP(hex_data):
    print("UDP hex dump: " + hex_data)
    fields = []
    fields.append(("Source Port", hex_data[0:4]))
    fields.append(("Destination Port", hex_data[4:8]))
    fields.append(("Length", hex_data[8:12]))
    fields.append(("Checksum", hex_data[12:16]))
    fields.append(("Data", hex_data[16:]))
    udp_table = create_table(fields)
    print(udp_table)

# Parse a IPv4 hex dump to get the necessary fields and then print out a table showing each fields and the corresponding value
def parse_IPv4(hex_data):
    fields = []
    fields.append(("Version", hex_data[0]))
    fields.append(("Internet Header length(IHL)", hex_data[1]))
    fields.append(("Type of Service", hex_data[2:4]))
    fields.append(("Total length", hex_data[4:8]))
    fields.append(("Identification", hex_data[8:12]))
    fields.append(("Flags", hex_data[12]))
    fields.append(("Fragment offset", hex_data[13:16]))
    fields.append(("Time to Live(TTL)", hex_data[16:18]))
    fields.append(("Protocol", hex_data[18:20]))
    fields.append(("Checksum", hex_data[20:24]))
    fields.append(("Source IP Address", hex_data[24:32]))
    fields.append(("Destination IP Address", hex_data[32:40]))

    # Check that IH: isnt greater than 5. If not then no options so rest of data is for Protocol so start at the last index
    ending_index = 40
    header_length_decimal = convert_hex_field_to_Decimal("IHL", hex_data[1])
    if  header_length_decimal > 5:
        num_of_diff_bytes = int(hex_data[1], 16) - 5
        num_of_chars = num_of_diff_bytes * 8
        #Update last index as there were IPv4 options in between the end of the IPv4 packet and the TCP packet starting 
        ending_index = 40 + num_of_chars
        fields.append(("Options", hex_data[40:ending_index]))
    print("IPv4 Table:")
    ipv4_table = create_table(fields)
    print(ipv4_table)
    # identify if tcp or udp and call aprropriate parse function
    protocol_decimal = convert_hex_field_to_Decimal("protocol", hex_data[18:20])
    protocol_hex_data = hex_data[ending_index:]
    if  protocol_decimal == 6:
        parse_TCP(protocol_hex_data)
    elif protocol_decimal == 17:
        parse_UDP(protocol_hex_data)
    else:
        print("Unknown protocol only parses TCP or UDP")

# Parse a ARP hex dump to get the necessary fields and then print out a table showing each fields and the corresponding value
def parse_ARP(hex_data):
    fields = []
    fields.append(("Hardware Address Type", hex_data[0:4]))
    fields.append(("Protocol Address Type", hex_data[4:8]))
    fields.append(("Hardware Address Length", hex_data[8:10]))
    fields.append(("Protocol Address Length", hex_data[10:12]))
    fields.append(("Opcode", hex_data[12:16]))
    fields.append(("Source Hardware Address", hex_data[16:28]))
    fields.append(("Source Protocol Address", hex_data[28:36]))
    fields.append(("Target Hardware Address", hex_data[36:48]))
    fields.append(("Target Protocol Address", hex_data[48:56]))

    arp_table = create_table(fields)
    print(arp_table)


# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()
    
    # Process the Ethernet header
    print(f"Captured Packet (Hex): {hex_data}")
    parse_ethernet_header(hex_data)
    ether_type = hex_data[24:28]
    hex_data_after_ether_type = hex_data[28:]
    print("Hex data after ether type: " + hex_data_after_ether_type)
    if ether_type == "0800":
        parse_IPv4(hex_data_after_ether_type)
    elif ether_type == "0806":
        parse_ARP(hex_data_after_ether_type)
    else:
        print("Unknown ether type only parses IPv4 and ARP")


# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)


# Make sure that the command line arguments have the necessary flags and associated values
def handle_args(args):
    if len(args) == 1:
        sys.exit("Error: No arguments provided need -i interface value and -p packet type(tcp,udp, or arp) ")
    
    flags = ["-i", "-p"]
    
    if len(args) > 5:
        sys.exit("Error: Too many arguments provided")
    
    for i in range(len(flags)):
        arg_label = ""
        if i == 0:
                arg_label += "interface name"
        else:
            arg_label += "packet type" 
        try:
            index = args.index(flags[i])
        except ValueError:
            sys.exit("Error: need " + flags[i] + " flag before " + arg_label)
        # Checks to see that there are no empty strings for values or that a value is skipped
        if (index + 1 >= len(args)) or (not args[index + 1].strip()) or (args[index + 1] in flags) :
            sys.exit("Error: no " + arg_label + " provided")  
    return args

# parse the arguments to find the values for each flag and checek that the values are correct
def parse_args(args):
    flags = ["-i", "-p"]
    parsed_values = []
    accepted_packet_types = ["tcp", "udp", "arp"]
    for i in range(len(flags)):
        index = args.index(flags[i])
        parsed_value = args[index + 1]
        parsed_values.append(str(parsed_value).lower())
        if(i == 1):
            if parsed_values[i] not in accepted_packet_types: 
                sys.exit("Invalid packet type! This program only accepts TCP,UDP, or ARP")
    return parsed_values 

# main function to run code
def main():
    cmd_args = sys.argv
    validated_args = handle_args(cmd_args)
    parsed_values = parse_args(validated_args)

    interface_name = parsed_values[0]
    packet_type = parsed_values[1]

    try: 
        capture_packets(str(interface_name), packet_type, 1)
    except OSError:
        sys.exit("Error Invalid interface name " + interface_name + "! Double check it is spelt right")

main()