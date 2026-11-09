import json

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


HOST = "0.0.0.0"
PORT = 8080

notes = {}
next_id = 1


class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # GET /
        if path == "/":
            self.send_response(200)
            self.end_headers()
            return

        # GET /echo?msg=<text>
        if path == "/echo":
            query_params = parse_qs(
                parsed_url.query,
                keep_blank_values=True
            )

            if "msg" not in query_params:
                self.send_response(400)
                self.end_headers()
                return

            message = query_params["msg"][0]

            response = {
                "msg": message
            }

            body = json.dumps(response).encode("utf-8")

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()

            self.wfile.write(body)
            return

        # GET /notes/<id>
        if path.startswith("/notes/"):
            note_id_string = path[len("/notes/"):]

            if not note_id_string.isdigit():
                self.send_response(404)
                self.end_headers()
                return

            note_id = int(note_id_string)

            if note_id not in notes:
                self.send_response(404)
                self.end_headers()
                return

            response = {
                "id": note_id,
                "text": notes[note_id]
            }

            body = json.dumps(response).encode("utf-8")

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json"
            )
            self.end_headers()

            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        global next_id

        parsed_url = urlparse(self.path)
        path = parsed_url.path

        # POST è supportato solo su /notes
        if path != "/notes":
            self.send_response(404)
            self.end_headers()
            return

        content_type = self.headers.get_content_type()

        if content_type != "application/json":
            self.send_response(415)
            self.end_headers()
            return

        content_length = int(
            self.headers.get("Content-Length", 0)
        )

        body = self.rfile.read(content_length)

        try:
            data = json.loads(body)

        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_response(400)
            self.end_headers()
            return

        if (
            not isinstance(data, dict)
            or "text" not in data
            or not isinstance(data["text"], str)
        ):
            self.send_response(400)
            self.end_headers()
            return

        note_id = next_id
        next_id += 1

        notes[note_id] = data["text"]

        response = {
            "id": note_id
        }

        response_body = json.dumps(response).encode("utf-8")

        self.send_response(201)
        self.send_header(
            "Content-Type",
            "application/json"
        )
        self.end_headers()

        self.wfile.write(response_body)

    def do_DELETE(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if not path.startswith("/notes/"):
            self.send_response(404)
            self.end_headers()
            return

        note_id_string = path[len("/notes/"):]

        if not note_id_string.isdigit():
            self.send_response(404)
            self.end_headers()
            return

        note_id = int(note_id_string)

        if note_id not in notes:
            self.send_response(404)
            self.end_headers()
            return

        del notes[note_id]

        self.send_response(204)
        self.end_headers()

    def do_PUT(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/notes":
            self.send_response(405)
            self.end_headers()
            return

        if path.startswith("/notes/"):
            note_id_string = path[len("/notes/"):]

            if not note_id_string.isdigit():
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(405)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def do_PATCH(self):
        self.do_PUT()


server = HTTPServer(
    (HOST, PORT),
    RequestHandler
)

print(
    f"HTTP server in ascolto sulla porta {PORT}..."
)

server.serve_forever()