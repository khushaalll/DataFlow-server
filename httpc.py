import ipaddress
import socket
import sys
import select
import json
import string
from packet import Packet

window_size = 5
base = 0
EOM = "<EOM>"
data_recv=["","","","",""]
count = 0


def help():
    print("httpc is a curl-like application but supports HTTP protocols only")
    print("Usage:")
    print("      get: executes a HTTP GET request and prints the response")
    print("     post: executes a HTTP POST request and prints the response")
    print("     help: prints this screen")
def getHelp():
    print("httpc help get")
    print("usage: httpc get [-v] [-h key:value] URL.")
    print("Get executes a HTTP GET request for a given  URL.")
    print("-v               Prints the detail of resppnse such as protocol, status and header")
    print("-h key:value     Associates headers to HTTP Request with the format 'key:value'")

def postHelp():
    print("httpc help post")
    print("usage: httpc get [-v] [-h key:value] [-d inline-data] [-f file] URL.")
    print("Post executes a HTTP POST request for a given URL with inline data or from file")
    print("-d string        Associates an inline data to the body HTTP POST request")
    print("-f file          Associates the content of a file to the body HTTP POST request")
    print("-v               Prints the detail of resppnse such as protocol, status and header")
    print("-h key:value     Associates headers to HTTP Request with the format 'key:value'")


def send_udp_msgs(data_chunks, conn,  peer_ip, server_port, router_addr, router_port, arr=None):
    timeout = 5
    windows = [0, 0, 0, 0, 0]
    response = ""
    for seq_num in range(base, min(base + window_size, len(data_chunks))):
        if arr is not None:
            if arr[seq_num] == 1:
                windows[seq_num] = 1
                continue
        chunk = data_chunks[seq_num]
        p = Packet(
            packet_type=0,
            seq_num=seq_num,
            peer_ip_addr=peer_ip,
            peer_port=server_port,
            payload=chunk.encode("utf-8")
        )

        conn.sendto(p.to_bytes(), (router_addr, router_port))

    conn.settimeout(timeout)

    try:
        while True:
            data, sender = conn.recvfrom(1024)
            print("sender: ", sender)
            p = Packet.from_bytes(data)
            print('Router: ', sender)
            print('Packet: ', p)
            #print('Payload: ' + p.payload.decode("utf-8"))
            if p.packet_type == 3:
                windows[p.seq_num] = 1
                allAcked = True
                for seq_num in range(base, min(base + window_size, len(data_chunks))):
                    if windows[seq_num] == 0:
                        allAcked = False
                        break
                if allAcked:
                    conn.settimeout(None)
            else:
                data_recv[p.seq_num] += (p.payload.decode("utf-8"))
                print("p.seq_num: ", p.seq_num)
                p.packet_type = 3
                #p.payload = "Send ACK".encode("utf-8")
                conn.sendto(p.to_bytes(), (router_addr, router_port))
                allDataReceived = True
                data_string = ""
                for i in range(window_size):
                    if data_recv[i] is None:
                        data_string  = ""
                        allDataReceived = False
                        break
                    data_string += data_recv[i]
                #print("data_string: ", data_string)
                if(allDataReceived):
                    print("window complete")
                    response += data_string
                if data_recv[p.seq_num][-5:] == EOM:
                    for i in range(p.seq_num):
                        if data_recv[i] is None:
                            allDataReceived = False
                            break
                    if(allDataReceived): 
                        print("Received all data")
                        print("Response: ", response)
                        conn.close()
                        break
    except socket.timeout:
        print('[CLIENT] - No response after %d for Packet %d ' % (timeout, p.seq_num))
        send_udp_msgs(data_chunks, conn, peer_ip, server_port, router_addr, router_port, windows)

    finally:
        conn.close()

def handshake(conn, router_addr, router_port, peer_ip, server_port, data_chunks):
    try:
        p = Packet(packet_type=1,
                   seq_num=1,
                   peer_ip_addr=peer_ip,
                   peer_port=server_port,
                   payload="".encode("utf-8"))
        conn.sendto(p.to_bytes(), (router_addr, router_port))
        print('******Three-way handshaking: Commnication from client******')
        print("Sending SYN - (PacketType = 1)")
        conn.settimeout(5)
        print('Waiting For A Response - Should be an SYN-ACK (PacketType = 2)')
        response, sender = conn.recvfrom(1024)
        p = Packet.from_bytes(response)
        print("Response recieved. PacketType =  ", p.packet_type)
        if p.packet_type == 2:
            print("Packet Type is a SynACK")
            p.packet_type = 3
            p.payload = "Send ACK".encode("utf-8")
            return True
        else:
            print("Three-way handshaking failed ! Didn't receive a SYN-ACK")
            sys.exit()
    except socket.timeout:
        print("No response received after 5 seconds")
        sys.exit()


def run_client(router_addr, router_port, server_addr, server_port, method, url, headers, data, verbose, fileToStore):
    peer_ip = ipaddress.ip_address(socket.gethostbyname(server_addr))
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timeout = 5
    url_parts = url.split('/')
    host_port = url_parts[2].split(':')
    host = host_port[0]
    port = int(host_port[1]) if len(host_port) > 1 else 80
    path = '/' + '/'.join(url_parts[3:])
    response_headers = {}
    response_body = ""
    print("host: ", host)   
    print("path: ", path)
    try:
        request = f"{method} {path} HTTP/1.1\r\n"
        request += f"Host: {host}\r\n"

        # Add headers to the request, if provided
        if headers:
            for header in headers:
                key, value = header
                print("in method ", key, " ", value)
                request += f"{key}: {value}\r\n"

        # Add Content-Length header for POST requests with data
        if method == "POST" and data:
            request += f"Content-Length: {len(data)}\r\n"

        request += "\r\n"

        # Add the request body for POST requests with data
        if method == "POST" and data:
            request += data

        request += EOM

        data_chunks = [request[i:i + 1013] for i in range(0, len(request), 1013)]
        print("data chunks , ", data_chunks)
        if(handshake(conn, router_addr, router_port, peer_ip, server_port, data_chunks)):
            send_udp_msgs(data_chunks, conn, peer_ip, server_port, router_addr, router_port)
        # msg=""
        # p = Packet(packet_type=0,
        #            seq_num=1,
        #            peer_ip_addr=peer_ip,
        #            peer_port=server_port,
        #            payload=msg.encode("utf-8"))
        # conn.sendto(p.to_bytes(), (router_addr, router_port))
        # print('Send "{}" to router'.format(msg))
        #
        # # Try to receive a response within timeout
        # conn.settimeout(timeout)
        # print('Waiting for a response')
        # response, sender = conn.recvfrom(1024)
        # p = Packet.from_bytes(response)
        # print('Router: ', sender)
        # print('Packet: ', p)
        # print('Payload: ' + p.payload.decode("utf-8"))

    except socket.timeout:
        print('No response after {}s'.format(timeout))
    finally:
        conn.close()

def main():

    if "--routerhost" in sys.argv:
        routerhost = sys.argv[sys.argv.index("--routerhost") + 1]
    else:
        routerhost = "localhost"
    if "--routerport" in sys.argv:
        routerport = sys.argv[sys.argv.index("--routerport") + 1]
    else:
        routerport = 3000
    if "--serverhost" in sys.argv:
        serverhost = sys.argv[sys.argv.index("--serverhost") + 1]
    else:
        serverhost = "localhost"
    if "--serverport" in sys.argv:
        serverport = sys.argv[sys.argv.index("--serverport") + 1]
    else:
        serverport = "8007"
    message = input("Enter the instructions GET/POST: ")
    message = message.split(" ")
    print(message[0])
    if message[0].lower() == "get" and message[-1].lower() == "help":
        getHelp()
    elif message[0].lower() == "post" and message[-1].lower() == "help":
        postHelp()
    else:

        fileToStore = None
        if "-o" in message:
            #  url=sys.argv[-3]
            fileToStore = message[message.index("-o") + 1]
        # else:
        url = message[-1]
        print("url ", url)
        method = message[0].upper()
        print("method: ", method)
        headerlist = []
        data = None
        file = None
        verbose = False
        if "-v" in message:
            verbose = True

        if message.count("-h") != 0:
            for i in range(len(message)):
                if message[i] == "-h":
                    headerlist.append(message[i + 1])
                    if len(headerlist) == message.count("-h"):
                        break
        if "-d" in message:
            data = message[message.index("-d") + 1]
        if "-f" in message:
            file = message[message.index("-f") + 1]
        # Find all occurrences of '-h' in message
        headerdict = []
        header_indices = [i for i, arg in enumerate(message) if arg == "-h"]
        count = 0
        for index in header_indices:
            # Check if the next argument is available
            if index + 1 < len(message):
                header = message[index + 1]
                # Split the header into key and value using ':'
                key, value = header.split(':', 1)
                # Add the header and value as a list to the headers list
                headerdict.append([key.strip(), value.strip()])
            else:
                print("Error: Header value is missing for -h option.")
                return
        if (method == "GET" and (not data and not file)) or (
                method == "POST" and ((data or not file) or (not data and file))):
            if file:
                try:
                    with open(file, 'r') as temp:
                        data = temp.read()
                except FileNotFoundError:
                    print(f"File not found: {file}")
                    return
            run_client(routerhost, routerport,serverhost,serverport,method, url, headerdict, data, verbose, fileToStore)


if __name__=="__main__":
    main()