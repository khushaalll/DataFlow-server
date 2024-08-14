import re
import socket
import sys
import os
import json
import xml.etree.ElementTree as ET
from threading import Thread
from packet import Packet
from collections import OrderedDict
import math

data_directory = os.getcwd()

openfile = []
window_size = 5
base = 0
EOM = "<EOM>"
data_recv=["","","","",""]
count = 0
def handle_msgs():
    return ""
def run_server(port, verbose, directory):
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        conn.bind(('', port))
        print('Echo server is listening at', port)
        data_recv = {}
        while True:
            data, sender = conn.recvfrom(1024)
            #print("sender :",sender[0], sender[1])
            p = Packet.from_bytes(data)
            if p.packet_type == 1:
                p.packet_type = 2
                p.payload = "SYN received, here is SYN_ACK ".encode("utf-8")
                conn.sendto(p.to_bytes(), sender)
            elif p.packet_type == 3:
                print("three way connection done")
            elif p.packet_type == 0:
                data = p.payload.decode()
                print("data ",data)
                p.packet_type = 3
                #p.payload = "Send ACK".encode("utf-8")
                conn.sendto(p.to_bytes(), sender)
                data_recv[p.seq_num] = (p.payload.decode("utf-8"))
                if data_recv[p.seq_num][-5:] == EOM:
                    data_recv[p.seq_num] = data_recv[p.seq_num][:-5]
                    allDataReceived = True
                    for i in range(p.seq_num):
                        if data_recv[i] is None:
                            allDataReceived = False
                            break
                    if allDataReceived:
                        msg = OrderedDict(sorted(data_recv.items()))
                        process_request(msg, conn, sender, p, verbose, directory)

                #send_udp_msgs1(data, conn, sender, p)
    except KeyboardInterrupt:
        print('Server terminated')



def process_request(data, conn, sender, p, verbose, data_directory):
    request_data = ""
    for val in data.values():
        request_data += val

    print("request ",request_data)
    headers, body = request_data.split("\r\n\r\n", 1)
    print("headers: ", headers)
    header_lines = headers.split("\r\n")
    request_line = header_lines[0]
    method, path, *_ = request_line.split(" ")


    request_dict = {
        "Method": method,
        "Path": path,
        "Headers": dict(line.split(": ", 1) for line in header_lines[1:])
    }
    overwrite = True
    if "overwrite" in request_dict.get("Headers"):
        if request_dict.get("Headers").get("overwrite").lower() == "false":
            overwrite = False

    if body:
        request_dict["Content"] = body.encode()
        request_dict["Content-Length"] = len(body.encode())
    print("***************")
    print(request_dict)
    print("***************")
    response = handle_request(request_dict, overwrite, verbose, data_directory)
    response += EOM
    print("response" , response)
    data_chunks = [response[i:i + 1013] for i in range(0, len(response), 1013)]
    print("data_chunks ",len(data_chunks))
    if(len(data_chunks) <= window_size):
        send_udp_msgs(data_chunks, conn, sender, p, verbose, data_directory)
    else:
        windows_needed = math.ceil(len(data_chunks) / window_size)
        print("windows_needed ",windows_needed)
        i = 0
        windows_sent = 0
        while windows_sent < windows_needed:
            print("i ",i)
            chunks = []
            for j in range (0, window_size):
                if i+j < len(data_chunks):
                    print("i+j ",i+j)
                    chunks.append(data_chunks[i+j])
            send_udp_msgs(chunks, conn, sender, p, verbose, data_directory)
            i = i+window_size
            windows_sent = windows_sent + 1
  


def handle_request(request, overwrite=False, verbose=False, data_directory=os.getcwd()):
    method = request["Method"]
    path = request["Path"]
    accept_header = request["Headers"].get("Accept", "").lower()
    file_path = ""
    try:
        if path.startswith("/..") or len(re.findall("/", path)) > 1:
            status_code = 400
            status_message = "Bad request"
            response_data =b"You cannot change directory"
            response = f"HTTP/1.1 {status_code} {status_message}\r\n"
            response += "Content-Length: {}\r\n\r\n".format(len(response_data))
            response += response_data.decode("utf-8")
            return response
        elif method == "GET" and path == "/":
            file_path = os.path.join(data_directory, path.lstrip("/"))
            if verbose:
                print(openfile)
            if file_path in openfile:
                if verbose:
                    print("into openfile if")
                status_code = 409
                status_message = "Conflict"
                response_data = b"File already being used by another client. Try after some time. Thanks"
                response = f"HTTP/1.1 {status_code} {status_message}\r\n"
                response += "Content-Length: {}\r\n\r\n".format(len(response_data))
                response += response_data.decode("utf-8")
                return response
            files = os.listdir(data_directory)
            response_data = format_response(files, accept_header)
            status_code = 200
            status_message = "OK"
            response_data = response_data.encode()
            response = f"HTTP/1.1 {status_code} {status_message}\r\n"
            response += "Content-Length: {}\r\n\r\n".format(response_data)
            response += response_data.decode("utf-8")
            return response
        elif method == "GET" and path.startswith("/"):
            file_path = os.path.join(data_directory, path.lstrip("/"))
            if file_path in openfile:
                status_code = 409
                status_message = "Conflict"
                response_data = b"File already being used by another client. Try after some time. Thanks"
                response = f"HTTP/1.1 {status_code} {status_message}\r\n"
                response += "Content-Length: {}\r\n\r\n".format(len(response_data))
                response += response_data.decode("utf-8")
                return response
            file_path = os.path.join(data_directory, path.lstrip("/"))
            if os.path.exists(file_path):
                with open(file_path, "rb") as file:
                    # Read and send file content in chunks
                    chunk_size = 1024
                    response_data = b""
                    while True:
                        chunk = file.read(chunk_size)
                        if not chunk:
                            break
                        response_data += chunk
                    status_code = 200
                    status_message = "OK"
                    response = f"HTTP/1.1 {status_code} {status_message}\r\n"
                    response += "Content-Length: {}\r\n\r\n".format(len(response_data))
                    response += response_data.decode("utf-8")
                    return response
            else:
                status_code = 404
                status_message = "Not found"
                response_data = b"Not found"
                response = f"HTTP/1.1 {status_code} {status_message}\r\n"
                response += "Content-Length: {}\r\n\r\n".format(len(response_data))
                response += response_data.decode("utf-8")
                return response

        elif method == "POST" and path.startswith("/"):
            if overwrite == True:
                t = "wb"
            else:
                t = "ab"

            print("path ", path )
            file_path = os.path.join(data_directory, path.lstrip("/"))
            print("file_path ",file_path)
            if verbose:
                print(file_path)
            if verbose:
                print(openfile)
            if file_path in openfile:
                status_code = 409
                status_message = "Conflict"
                response_data = b"File already being used by another client. Try after some time. Thanks"
                response = f"HTTP/1.1 {status_code} {status_message}\r\n"
                response += "Content-Length: {}\r\n\r\n".format(len(response_data))
                response += response_data.decode("utf-8")
                return response
            else:
                openfile.append(file_path)
                content_length = int(request.get("Content-Length", 0))
                content = request.get("Content", b"")
                with open(file_path, t) as file:
                    file.write(content)
                status_code = 200
                status_message = "OK"
                response_data = b"File created/overwritten successfully"
                response = f"HTTP/1.1 {status_code} {status_message}\r\n"
                response += "Content-Length: {}\r\n\r\n".format(len(response_data))
                response += response_data.decode("utf-8")
                openfile.remove(file_path)
                return response
        else:
            status_code = 400
            status_message = "Bad request"
            response_data = b"Invalid Request"
            response = f"HTTP/1.1 {status_code} {status_message}\r\n"
            response += "Content-Length: {}\r\n\r\n".format(len(response_data))
            response += response_data.decode("utf-8")
            return response
    except Exception as e:
        status_code = 500
        status_message = "Internal Server Error"
        response_data = str(e).encode()
        response = f"HTTP/1.1 {status_code} {status_message}\r\n"
        response += "Content-Length: {}\r\n\r\n".format(len(response_data))
        response += response_data.decode("utf-8")
        openfile.remove(file_path)
        return response

def format_response(data, accept_header):
    if "application/json" in accept_header:
        return json.dumps(data)
    elif "application/xml" in accept_header:
        root = ET.Element("root")
        for item in data:
            ET.SubElement(root, "file").text = item
        return ET.tostring(root, encoding="utf-8").decode()
    elif "text/plain" in accept_header:
        return "\n".join(data)
    else:  # default to HTML
        html_content = "<ul>"
        for item in data:
            html_content += f"<li>{item}</li>"
        html_content += "</ul>"
        return html_content
    
def send_udp_msgs(data_chunks, conn, sender, p, arr=None):
    timeout = 5
    windows = [0, 0, 0, 0, 0]
    
    for seq_num in range(base, min(base + window_size, len(data_chunks))):
        if arr is not None:
            if arr[seq_num] == 1:
                windows[seq_num] = 1
                continue
        chunk = data_chunks[seq_num]
        p.seq_num = seq_num
        p.payload = chunk.encode("utf-8")
        p.packet_type = 0
        conn.sendto(p.to_bytes(), sender)

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
                print("windows ", windows)
                if allAcked:
                    print("in all ack")
                    conn.settimeout(None)
                    break
            else:
                data_recv[p.seq_num] += (p.payload.decode("utf-8"))
                p.packet_type = 3
                conn.sendto(p.to_bytes(), sender)
                allDataReceived = True
                data_string = ""
                if data_recv[p.seq_num][-5:] == EOM:
                    for i in range(p.seq_num):
                        data_string += data_recv[p.seq_num]
                        if data_recv[i] is None:
                            allDataReceived = False
                            break
                    if allDataReceived:
                        print(data_recv)
    except socket.timeout:
        print('[Server] - No response after %d for Packet %d ' % (timeout, p.seq_num))
        send_udp_msgs(data_chunks, conn, sender, p, windows)

def main():
    verbose =  False
    if "-v" in sys.argv:
        verbose = True
        print("setting verbose to true")
    if "-p" in sys.argv:
        port = sys.argv[sys.argv.index("-p")+1]
    else:
        port = 8007
    if "-d" in sys.argv:
        directory = sys.argv[sys.argv.index("-d")+1]
    else:
        directory = os.getcwd()
    #send request to function
    run_server(port, verbose, directory)


if __name__ == "__main__":
    main()
