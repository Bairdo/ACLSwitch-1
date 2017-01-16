from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn

import os
import signal
import sys
import lockfile
import psutil

from urlparse import parse_qs

PATH_PREFIX = "/v1.0/"
AUTH_PATH = PATH_PREFIX + "authenticate/"
IDLE_PATH = PATH_PREFIX + "idle/"
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
        if self.path.startswith(AUTH_PATH):
            self.authenticate()
        elif self.path.startswith(IDLE_PATH):
            self.idle()        
        else:
            self._set_headers(404, 'text/html')
            error = 'Path not found\n'
            print error
            self.wfile.write(error)     
            return 
    
    def do_DELETE(self):
        if self.path.startswith(AUTH_PATH):
            form = self.path[len(AUTH_PATH):] #remove the auth_path part of the string
            info = parse_qs(form)
            if "ip" in info and "user" in info:
                self.deauthenticate(self.capflow_file, info["ip"][0], info["user"][0], signal.SIGUSR2)
            elif "mac" in info and "user" in info:
               self.deauthenticate(self.dot1x_active_file, info["mac"][0], info["user"][0], signal.SIGUSR1)
            else:
                self.send_error('Invalid form\n')
                return
        else:
            self.send_error('Path not found\n')
            return
    
    def authenticate(self):
        form = self.path[len(AUTH_PATH):] #remove the auth_path part of the string
        info = parse_qs(form)
        
        if "ip" in info and "user" in info:
            self.write_to_file(self.capflow_file, info["ip"][0], info["user"][0])
            self.send_signal(signal.SIGUSR2)
        elif "mac" in info and "user" in info:
            self.write_to_file(self.dot1x_active_file, info["mac"][0], info["user"][0])
            self.send_signal(signal.SIGUSR1)
        else:
            self.send_error('Invalid form\n')     
            return
        
        self._set_headers(200, 'text/html')
        message = "authenticated new client" 
        print message
        self.wfile.write(message)     
        
    def idle(self):
        form = self.path[len(IDLE_PATH):] #remove the idle_path part of the string
        info = parse_qs(form)
        
        if not ("mac" in info and "retrans" in info):
            self.send_error("Invalid form\n")
            return
        
        self.write_to_file(self.dot1x_idle_file, info["mac"][0], info["retrans"][0])
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
        message = "deauthenticated client" 
        print message
        self.wfile.write(message)     
        
    def write_to_file(self, filename, str1, str2):
        fd = lockfile.lock(filename, os.O_APPEND | os.O_WRONLY)
        print str1
        print str2
        string = str1 + "," + str2 + "\n"
        os.write(fd, string)
        lockfile.unlock(fd)
    
    def read_file(self,filename, unique_identifier, user):
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
    
