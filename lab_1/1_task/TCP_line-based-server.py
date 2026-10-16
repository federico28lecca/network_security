import socket
import threading


HOST = "0.0.0.0"
PORT = 9001

store = {}
store_lock = threading.Lock()


def handle_command(command):
    if command == "PING":
        return "PONG"

    if command.startswith("ECHO "):
        return command[5:]

    if command.startswith("SET "):
        rest = command[4:]

        key, separator, value = rest.partition(" ")

        if not key or not separator or not value:
            return "ERR"

        with store_lock:
            store[key] = value

        return "OK"

    if command.startswith("GET "):
        key = command[4:]

        if not key or " " in key:
            return "ERR"

        with store_lock:
            if key in store:
                return store[key]

        return "NOT_FOUND"

    return "ERR"


def handle_client(connection, address):
    print(f"Client connesso: {address}")

    with connection:
        buffer = b""

        while True:
            data = connection.recv(4096)

            if not data:
                break

            buffer += data

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)

                if line.endswith(b"\r"):
                    line = line[:-1]

                command = line.decode("ascii")

                print(f"{address} -> {command!r}")

                response = handle_command(command)

                connection.sendall(
                    (response + "\n").encode("ascii")
                )

                print(f"{address} <- {response!r}")

    print(f"Client disconnesso: {address}")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind((HOST, PORT))

    server_socket.listen()

    print(f"Server in ascolto sulla porta {PORT}...")

    while True:
        connection, address = server_socket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(connection, address),
            daemon=True
        )

        thread.start()