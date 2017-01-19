from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn

import os
import signal
import sys
import lockfile
import psutil
import json
import cgi

CAPFLOW = "/v1.1/authenticate/auth"
AUTH_PATH = "/authenticate/auth"
IDLE_PATH = "/idle"
class HTTPHandler(BaseHTTPRequestHandler):

    _contr_pid = -1
    dot1x_active_file = os.getenv('DOT1X_ACTIVE_HOSTS', '/etc/ryu/1x_active_users.txt')
    dot1x_idle_file = os.getenv('DOT1X_IDLE_HOSTS', '/etc/ryu/1x_idle_users.txt')
    capflow_file = os.getenv('CAPFLOW_CONFIG','/etc/ryu/capflow_config.txt')
        
    def _set_headers(self,code,ctype):
        self.send_response(code)
        self.send_header('Content-type', ctype)
        self.end_headers()

    def do_POST(self):
        json_data = self.check_if_json()
        if json_data == None:
            return
            
        if self.path == AUTH_PATH or self.path == CAPFLOW:
            self.authenticate(json_data)
        elif self.path == IDLE_PATH:
            self.idle(json_data)        
        else:
            self.send_error('Path not found\n')
            
   
    def do_DELETE(self):
        json_data = self.check_if_json()
        if json_data == None:
            return
            
        if self.path == AUTH_PATH:
            #check json has the right information
            if not (json_data.has_key("mac") and json_data.has_key("user")):
                self.send_error('Invalid form\n')
                return
            self.deauthenticate(self.dot1x_active_file, json_data["mac"], signal.SIGUSR1)
        elif self.path == CAPFLOW:
            #check json has the right information
            if not (json_data.has_key("ip")):
                self.send_error('Invalid form\n')
                return
            self.deauthenticate(self.capflow_file, json_data["ip"], signal.SIGUSR2)
        else:
            self.send_error('Path not found\n')
            
    
    def authenticate(self, json_data):
        if self.path == AUTH_PATH:
            if not (json_data.has_key("mac") and json_data.has_key("user")):
                self.send_error('Invalid form\n')
                return            
            self.write_to_file(self.dot1x_active_file, json_data["mac"], json_data["user"])
            self.send_signal(signal.SIGUSR1)
        
        else:
            if not (json_data.has_key("ip") and json_data.has_key("user")):
                self.send_error('Invalid form\n')
                return
            self.write_to_file(self.capflow_file, json_data["ip"], json_data["user"])
            self.send_signal(signal.SIGUSR2)
        
        self._set_headers(200, 'text/html')
        message = "authenticated new client" 
        print message
        self.wfile.write(message)
        
    def idle(self, json_data):
        if not (json_data.has_key("mac") and json_data.has_key("retrans")):
            self.send_error("Invalid form\n")
            return
        
        self.write_to_file(self.dot1x_idle_file, json_data["mac"], json_data["retrans"])
        self.send_signal(signal.SIGUSR1)
        self._set_headers(200, 'text/html')
        message = "Idle user has been made to use captive portal"
        print message
        self.wfile.write(message)
        
    def deauthenticate(self, filename, unique_identifier, user, signal_type):
        fd = lockfile.lock(filename, os.O_APPEND | os.O_WRONLY)
        changed, to_write = self.read_file(filename, unique_identifier, user)
        if changed:
            os.ftruncate(fd,0)
            os.write(fd, to_write)
        lockfile.unlock(fd)
        self.send_signal(signal_type)
        
        self._set_headers(200, 'text/html')
        message = "deauthenticated client\n" 
        print message
        self.wfile.write(message)
        
    def write_to_file(self, filename, str1, str2):
        fd = lockfile.lock(filename, os.O_APPEND | os.O_WRONLY)
        print str1
        print str2
        string = str(str1) + "," + str(str2) + "\n"p
        os.write(fd, string)
        lockfile.unlock(fd)
    
    def read_file(self,filename, unique_identifier):
        to_write = ""
        file_changed = False
        with open(filename) as file_:
            for line in file_:
                unique_identifier1, user1= line.split(",")
                if unique_identifier != unique_identifier1:
                    to_write += line
                else:
                    file_changed = True

        return file_changed, to_write
    
    def send_signal(self, signal_type):
        if self._contr_pid < 0:
            for process in psutil.process_iter():
                if process.name() == "ryu-manager" and any("controller.py" in s for s in process.cmdline()):
                    self._contr_pid = process.pid
                    break
        os.kill(self._contr_pid,signal_type)  
    
    def check_if_json(self):
        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        if ctype != 'application/json':
            self.send_error("Data is not a JSON object\n")
            return None
        content_length = int(self.headers.getheader('content-length'))
        data = self.rfile.read(content_length)
        try:
            json_data = json.loads(data)
        except ValueError:
             self.send_error("Not JSON object\n")
             return None
        
        return json_data
    
    def send_error(self,error):
        self._set_headers(404, 'text/html')
        print error
        self.wfile.write(error)  

    do_GET = do_POST
        
    
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass
    
if __name__ == "__main__":
    server = ThreadedHTTPServer(('', 8080), HTTPHandler)
    print "starting server"
    server.serve_forever()
    
