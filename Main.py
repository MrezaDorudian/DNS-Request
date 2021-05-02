import socket
import random
import binascii
from collections import OrderedDict
import csv
import dnslib.dns


DNS_PORT = 53  # DNS is on port 53
DNS_SERVER_1 = '1.1.1.1'  # cloudflare
DNS_SERVER_2 = '8.8.8.8'  # google.com
DNS_SERVER_3 = '199.9.14.201'  # root server


# created a UDP message to send
def create_message(is_recursive, nameAddress, queryType='A'):
    # generate a random ID for the request
    ID = random.randint(0, 65535)
    # setting the flags
    QR = 0
    OPCODE = 0
    AA = 0
    TC = 0
    RD = 1
    RA = 0
    if not is_recursive:
        RD = 0
    Z = 0
    RCODE = 0

    queryFlags = str(QR)
    queryFlags += str(OPCODE).zfill(4)
    queryFlags += str(AA) + str(TC) + str(RD) + str(RA)
    queryFlags += str(Z).zfill(3)
    queryFlags += str(RCODE).zfill(4)
    queryFlags = '{:04x}'.format(int(queryFlags, 2))
    # flags ready

    # Question part
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    message = ''
    message += "{:04x}".format(ID)
    message += queryFlags
    message += '{:04x}'.format(QDCOUNT)
    message += '{:04x}'.format(ANCOUNT)
    message += '{:04x}'.format(NSCOUNT)
    message += '{:04x}'.format(ARCOUNT)

    addressParts = nameAddress.split('.')
    QNAME = ''
    for part in addressParts:
        length = '{:02x}'.format(len(part))
        text = binascii.hexlify(part.encode())
        QNAME += length
        QNAME += text.decode()
    QNAME += '00'
    message += QNAME

    QTYPE = get_type(queryType)
    message += QTYPE

    QCLASS = 1
    message += '{:04x}'.format(QCLASS)
    # message ready
    return message


# get dns record type as bytes
def get_type(queryType):
    types = [
             "ERROR", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB",
             "MG", "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT"
            ]
    return "{:04x}".format(types.index(queryType)) if isinstance(queryType, str) else types[queryType]


# send the created message to the given server and get the answer
def send_message(msg, dns_server, port):
    msg = msg.replace(" ", "").replace("\n", "")
    server = (dns_server, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(binascii.unhexlify(msg), server)
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        print('\n\ntimeout (server did not answer after 3 seconds.)')
        return -999
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")


# this function is used in decode_message function for decoding
def parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]

    if len(part_len) == 0:
        return parts

    part_end = part_start + (int(part_len, 16) * 2)
    parts.append(message[part_start:part_end])

    if message[part_end:part_end + 2] == "00" or part_end > len(message):
        return parts
    else:
        return parse_parts(message, part_end, parts)


# decode the input message
def decode_message(message):
    res = []

    ID = message[0:4]
    query_params = message[4:8]
    QDCOUNT = message[8:12]
    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20]
    ARCOUNT = message[20:24]

    params = "{:b}".format(int(query_params, 16)).zfill(16)
    QPARAMS = OrderedDict([
        ("QR", params[0:1]),
        ("OPCODE", params[1:5]),
        ("AA", params[5:6]),
        ("TC", params[6:7]),
        ("RD", params[7:8]),
        ("RA", params[8:9]),
        ("Z", params[9:12]),
        ("RCODE", params[12:16])
    ])

    # Question section
    QUESTION_SECTION_STARTS = 24
    question_parts = parse_parts(message, QUESTION_SECTION_STARTS, [])

    QNAME = ".".join(map(lambda p: binascii.unhexlify(p).decode(), question_parts))

    QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(question_parts))) + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4

    QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]
    QCLASS = message[QCLASS_STARTS:QCLASS_STARTS + 4]

    res.append("\n# HEADER")
    res.append("ID: " + ID)
    res.append("QUERYPARAMS: ")
    for qp in QPARAMS:
        res.append(" - " + qp + ": " + QPARAMS[qp])
    res.append("\n# QUESTION SECTION")
    res.append("QNAME: " + QNAME)
    res.append("QTYPE: " + QTYPE + " (\"" + get_type(int(QTYPE, 16)) + "\")")
    res.append("QCLASS: " + QCLASS)

    # Answer section
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4

    NUM_ANSWERS = max([int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)])
    if NUM_ANSWERS > 0:
        res.append("\n# ANSWER SECTION")

        for ANSWER_COUNT in range(NUM_ANSWERS):
            if (ANSWER_SECTION_STARTS < len(message)):
                ANAME = message[ANSWER_SECTION_STARTS:ANSWER_SECTION_STARTS + 4]  # Refers to Question
                ATYPE = message[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
                ACLASS = message[ANSWER_SECTION_STARTS + 8:ANSWER_SECTION_STARTS + 12]
                TTL = int(message[ANSWER_SECTION_STARTS + 12:ANSWER_SECTION_STARTS + 20], 16)
                RDLENGTH = int(message[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
                RDDATA = message[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

                if ATYPE == get_type("A"):
                    octets = [RDDATA[i:i + 2] for i in range(0, len(RDDATA), 2)]
                    RDDATA_decoded = ".".join(list(map(lambda x: str(int(x, 16)), octets)))
                else:
                    RDDATA_decoded = ".".join(
                        map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(RDDATA, 0, [])))

                ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)

            try:
                ATYPE
            except NameError:
                None
            else:
                res.append("# ANSWER " + str(ANSWER_COUNT + 1))
                res.append("QDCOUNT: " + str(int(QDCOUNT, 16)))
                res.append("ANCOUNT: " + str(int(ANCOUNT, 16)))
                res.append("NSCOUNT: " + str(int(NSCOUNT, 16)))
                res.append("ARCOUNT: " + str(int(ARCOUNT, 16)))

                res.append("ANAME: " + ANAME)
                res.append("ATYPE: " + ATYPE + " (\"" + get_type(int(ATYPE, 16)) + "\")")
                res.append("ACLASS: " + ACLASS)

                res.append("\nTTL: " + str(TTL))
                res.append("RDLENGTH: " + str(RDLENGTH))
                res.append("RDDATA: " + RDDATA)
                res.append("RDDATA decoded (result): " + RDDATA_decoded + "\n")

    return RDDATA_decoded


# create a .csv file including some name addresses
def create_input_csv():
    with open('input.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['No.', 'Name Address'])
        writer.writerow([1, 'google.com'])
        writer.writerow([2, 'yahoo.com'])
        writer.writerow([3, 'twitter.com'])
        writer.writerow([4, 'store.steampowered.com'])
        writer.writerow([5, 'imdb.com'])
        writer.writerow([6, 'weather.com'])
        writer.writerow([7, 'amazon.com'])
        writer.writerow([8, 'facebook.com'])
        writer.writerow([9, 'instagram.com'])
        writer.writerow([10, 'ebay.com'])


# read from the .csv file and return the name addresses
def read_csv():
    output = []
    with open('input.csv', 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            output.append(row)
    return output[1:]


# save the output data to a .csv file
def save_to_csv(name_addresses, IPs, iterations, isrecursive):
    with open('output.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        if isrecursive:
            writer.writerow(['No.', 'Name Address', 'Returned IP-address'])
            for i in range(len(name_addresses)):
                writer.writerow([i + 1, name_addresses[i], IPs[i]])
        else:
            writer.writerow(['No.', 'Name Address', 'Returned IP-address', 'Iterations'])
            for i in range(len(name_addresses)):
                writer.writerow([i + 1, name_addresses[i], IPs[i], iterations[i]])


# finds the IP of name address that user types
def user_input():
    name_address = input('Enter a name address:\n')
    query_type = input('Enter a query_type(e.g. A):\n')
    message_to_send = create_message(True, name_address, query_type)
    answer = send_message(message_to_send, DNS_SERVER_1, DNS_PORT)
    if answer == -999:
        return
    IP = decode_message(answer)
    print(f'The IP address that the query type [{query_type}] returned, is:\n[{name_address}] --- ({IP})')


def iterative_call(name_address, query_type='A'):
    iteration_counter = 1
    server_ip_to_send = DNS_SERVER_3
    IPs_to_request_again = []
    while True:
        if iteration_counter > 50:
            print('\n\nIteration Exceeded 50 and it could not find the IP address.')
            return False, 50
        print('==============================================================')
        print(f'iteration [{iteration_counter}]')
        message_to_send = create_message(False, name_address, query_type)
        answer = send_message(message_to_send, server_ip_to_send, DNS_PORT)
        if answer == -999:
            return False, -999
        output = dnslib.dns.DNSRecord.parse(binascii.unhexlify(answer))
        isServerAnsweredUs = int(output.format().split('\n')[0].split('a=')[1][0])
        # the dns server found the IP and answered us
        if isServerAnsweredUs == 1:
            IP = output.format().split('\n')[2].split('rdata=')[1].replace('\'', '').replace('>', '')
            print(f'Found by: {server_ip_to_send}')
            print(f'The IP address that the query type [{query_type}] returned, is:\n[{name_address}] --- ({IP})')
            return True, (IP, iteration_counter)
        else:
            print(f'The Server with IP: ({server_ip_to_send}) could not answer our query.')
            output = output.format().split('.\'>')[-1].split('\n')
            for i in range(len(output)):
                if i == 0:
                    continue
                if 'rdata' in output[i]:
                    rawIP = output[i].split('rdata')[1].replace('=\'', '').replace('\'>', '')
                    # only take the IPV4 protocol
                    if rawIP.count(':') == 0:
                        if rawIP not in IPs_to_request_again:
                            IPs_to_request_again.append(rawIP)
            if len(IPs_to_request_again) == 0:
                print(f'Now we should ask among these IPs:\n{IPs_to_request_again}')
                print('\n\nNo more IPs to search among.')
                return False, 0
            server_ip_to_send = IPs_to_request_again.pop(random.randint(0, len(IPs_to_request_again) - 1))
            print(f'Now we should ask among these IPs:\n{IPs_to_request_again}')
            print(f'Now we are asking server with IP: ({server_ip_to_send})')
            # IPs_to_request_again.clear()
        iteration_counter += 1


def iterative_user_input():
    name_address = input('Enter a name address:\n')
    query_type = input('Enter a query_type(e.g. A):\n')
    iterative_call(name_address, query_type)


# finds IPs of name addresses that is available in
# a .csv file and saves it into another .csv file
def csv_input():
    name_addresses = []
    IPs = []
    create_input_csv()
    output = read_csv()
    print('The IP address that the query returned is:')
    for name_address in output:
        name_addresses.append(name_address[1])
        message_to_send = create_message(True, name_address[1])
        answer = send_message(message_to_send, DNS_SERVER_1, DNS_PORT)
        if answer == -999:
            IPs.append('timeout (server did not answer).')
            print('timeout (server did not answer).')
        else:
            IP = decode_message(answer)
            if 'd' in IP:
                IPs.append('Could not find the IP.')
                print(f'Could not find the IP.')
            else:
                IPs.append(IP)
                print(f'[{name_address[1]}] --- ({IP})')

    save_to_csv(name_addresses, IPs, None, True)
    print('\n\nSaved successfully to the output file!')


def iterative_csv_input():
    name_addresses = []
    IPs = []
    iterations = []
    create_input_csv()
    output = read_csv()
    for name_address in output:
        name_addresses.append(name_address[1])
        state = iterative_call(name_address[1])
        # state == -999 --> timeout.
        # state == 50 --> iteration exceeded 50.
        # state == 0 --> no more server to search.
        # else --> the output IP
        if not state[0]:
            if state[1] == -999:
                IPs.append('timeout (server did not answer).')
                iterations.append('NAN')
                print(f'[{name_address[1]}] --- (timeout (server did not answer).) --- NAN iteration')
            elif state[1] == 50:
                IPs.append('Iteration Exceeded 50.')
                iterations.append(50)
                print(f'[{name_address[1]}] --- (Iteration Exceeded 50.) --- {50} iteration')
            elif state[1] == 0:
                print(f'[{name_address[1]}] --- (No more IPs to search among.) --- NAN iteration')
                iterations.append('NAN')
                IPs.append('No more IPs to search among.')
        else:
            if 'd' in state[1][0]:
                print(f'[{name_address[1]}] --- (Could not find the IP.) --- {state[1][1]} iteration')
                IPs.append('Could not find the IP.')
                iterations.append('NAN')
            else:
                IPs.append(state[1][0])
                iterations.append(state[1][1])
                print(f'[{name_address[1]}] --- ({state[1][0]}) --- {state[1][1]} iteration')
    save_to_csv(name_addresses, IPs, iterations, False)
    print('\n\nSaved successfully to the output file!')


def recursive_query():
    is_csv = int(input('choose 1 for [csv input] or 2 for [user input]:\n'))
    if is_csv == 1:
        csv_input()
    else:
        user_input()


def iterative_query():
    is_csv = int(input('choose 1 for [csv input] or 2 for [user input]:\n'))
    if is_csv == 1:
        iterative_csv_input()
    else:
        iterative_user_input()
    pass


def query():
    is_recursive = int(input('choose 1 for [recursive] or 2 for [iterative]:\n'))
    if is_recursive == 1:
        recursive_query()
    else:
        iterative_query()


if __name__ == '__main__':
    query()