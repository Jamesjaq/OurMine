import socket
import threading

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            # Modbus TCP Header: [Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1), Function Code (1), Data (n)]
            # Just respond with a dummy success for any request
            # Transaction ID matches request, Protocol 0, Length 3, Unit 1, Function Code, Data 0
            response = data[:4] + b'\x00\x03\x01' + data[7:8] + b'\x01'
            client_socket.send(response)
            print(f"Handled Modbus request: {data.hex()}")
        except:
            break
    client_socket.close()

def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 5020))
    server.listen(5)
    print("Simple Modbus Mock Server listening on 127.0.0.1:5020")
    while True:
        client, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

if __name__ == "__main__":
    run_server()
