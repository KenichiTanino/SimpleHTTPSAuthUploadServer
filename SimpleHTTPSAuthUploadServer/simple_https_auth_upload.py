#!/usr/bin/env python

"""Simple HTTP Server With HTTPS and Upload and Authentication.
This module builds on BaseHTTPServer by implementing the standard GET
and HEAD requests in a fairly straightforward manner.
Thanks to: https://gist.github.com/csaki/9b482f45710470ed58723d224ef9112c
"""

import argparse
import base64
import os
import posixpath
import http.server
import urllib.request
import urllib.parse
import urllib.error
import cgi
import html
import mimetypes
from io import BytesIO
import ssl
import socket
import sys
import logging
from socketserver import TCPServer

from . import cert
from . import __prog__
from . import __version__

logger = logging.getLogger(__file__)


key = ""


class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Simple HTTP request handler with GET/HEAD/POST commands.
    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method. And can reveive file uploaded
    by client.
    The GET/HEAD/POST requests are identical except that the HEAD
    request omits the actual contents of the file.
    https://github.com/python/cpython/blob/3.8/Lib/http/server.py
    """

    server_version = "SimpleHTTPSWithAuthUpload/" + __version__

    def __init__(self, *args, directory=None, **kwargs):
        if directory is None:
            directory = os.getcwd()
        self.directory = directory
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        """Serve a HEAD request."""
        f = self.send_head()
        if f:
            f.close()

    def is_authenticated(self):
        global key
        auth_header = self.headers['Authorization']
        return auth_header and auth_header == 'Basic ' + key.decode()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def try_authenticate(self):
        if not key:
            return True
        if not self.is_authenticated():
            self.do_AUTHHEAD()
            logger.info('not authenticated')
            self.wfile.write(b'not authenticated')
            return False
        return True

    def do_GET(self):
        if not self.try_authenticate():
            return
        logger.info('authenticated')

        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def do_POST(self):
        if not self.try_authenticate():
            return
        logger.info('authenticated')

        """Serve a POST request."""
        result, info = self.deal_post_data()
        logger.info(result, info, "by: ", self.client_address)
        r = []
        enc = sys.getfilesystemencoding()
        r.append('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        r.append("<html>\n<title>Upload Result Page</title>\n")
        r.append("<body>\n<h2>Upload Result Page</h2>\n")
        r.append("<hr>\n")
        if result:
            r.append("<strong>Success:</strong>")
        else:
            r.append("<strong>Failed:</strong>")
        r.append(info)
        r.append("<br><a href=\"%s\">back</a>" % self.headers['referer'])
        r.append("<hr><small>Powerd By: user, check new version at ")
        r.append("<a href=\"http://localhost/?s=SimpleHTTPSAuthUploadServer\">")
        r.append("here</a>.</small></body>\n</html>\n")
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if f:
            self.copyfile(f, self.wfile)
            f.close()

    def parse_multipart_form(self, body):
        environ = {'REQUEST_METHOD': 'POST'}

        fs = cgi.FieldStorage(fp=body, environ=environ, headers=self.headers)
        for f in fs.list:
            return(f.filename, f.value)

    def deal_post_data(self):
        filename, data = self.parse_multipart_form(self.rfile)
        path = self.translate_path(self.path)
        fn = os.path.join(path, filename)
        try:
            out = open(fn, 'wb')
        except IOError:
            return (False, "Can't create file to write, do you have permission to write?")

        out.write(data)
        out.close()
        return (True, "File '%s' upload success!" % filename)

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).
        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().
        """
        try:
            list = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        list = ['..'] + list
        r = []
        displaypath = cgi.escape(urllib.parse.unquote(self.path))
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(path)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        r.append('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        r.append("<html>\n<title>Directory listing for %s</title>\n" % displaypath)
        r.append("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath)
        r.append("<hr>\n")
        r.append("<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
        r.append("<input name=\"file\" type=\"file\"/>")
        r.append("<input type=\"submit\" value=\"upload\"/></form>\n")
        r.append("<hr>\n<ul>\n")
        for name in list:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
            r.append('<li><a href="%s">%s</a>\n' % (urllib.parse.quote(linkname),
                                                    html.escape(displayname)))
        r.append("</ul>\n<hr>\n</body>\n</html>\n")
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def guess_type(self, path):
        """Guess the type of a file.
        Argument is a PATH (a filename).
        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.
        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.
        """

        # The text attribute assumes UTF-8
        self.extensions_map = {k: v if 'text/' not in v else v + ';charset=UTF-8'
                               for k, v in self.extensions_map.items()}
        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init()  # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',  # Default
        '.pdf': 'application/octet-stream',
        '.py': 'text/plain',
        '.tex': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
    })


def serve_https(https_port=80, https=True, start_dir=None, handler_class=SimpleHTTPRequestHandler):
    ''' setting up server '''
    TCPServer.allow_reuse_address = True
    httpd = TCPServer(("", https_port), handler_class)

    if https:
        # If you use SSL, create a ".ssl" directory under your boot directory and
        # store your private key and certificate in it.
        keyfile, certfile = cert.create_ssl_cert(socket.gethostname())
        httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=keyfile,
                                       certfile=certfile, server_side=True)

    if start_dir:
        logger.info("Changing dir to {cd}".format(cd=start_dir))
        os.chdir(start_dir)

    socket_addr = httpd.socket.getsockname()
    print("Serving HTTP on", socket_addr[0], "port", socket_addr[1], "use <Ctrl-C> to stop...")
    httpd.serve_forever()


def main():
    global key
    parser = argparse.ArgumentParser(prog=__prog__)
    parser.add_argument('--port', '-p', type=int, default=8000, help='port number(default 8000)')
    parser.add_argument('--auth', '-a', default='', help='username:password')
    parser.add_argument('--dir', required=False, help='directory')
    parser.add_argument('--https', help='Use https', action='store_true', default=False)
    args = parser.parse_args()

    key = base64.b64encode(args.auth.encode())

    serve_https(int(args.port), https=args.https,
                start_dir=args.dir, handler_class=SimpleHTTPRequestHandler)


if __name__ == '__main__':
    main()
