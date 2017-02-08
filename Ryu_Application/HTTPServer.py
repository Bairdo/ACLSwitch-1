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

    _contr_pid = -1 #the process ID of the controller
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
    
    def update_file(self, filename, token1, token2):
    '''
    Typically token1 will be the mac address,
    And token2 will be the username or the idle_count.
    '''
        fd = lockfile.lock(filename, os.O_RDWR)
        text = ""

        # read file 100 bytes at a time
        while True:
            s = os.read(fd, 100)
            if len(s) != 0:
                text = text + s
            else:
                break
        print "text " + text
        # go back to start of file.
        os.lseek(fd, 0, os.SEEK_SET)
        # set the file length to 0, (clear the file)
        os.ftruncate(fd, 0)

        if len(text) == 0:
            os.write(fd, token1 + "," + token2 + "\n")
        else:
            flag = False
            for l in text.split("\n"):
                print "L: " + l
                if len(l) != 0:
                    splits = l.split(",")
                    print "splits " + str(splits)
                    ltoken1 = splits[0]
                    ltoken2 = splits[1]
                    if ltoken1 == token1:
                        print  + "macs are the same"
                        os.write(fd, token1 + "," + token2 + "\n")
                        flag = True
                    else:
                        print ltoken1 + " " + token1 + " are different"
                        os.write(fd, ltoken1 + "," + ltoken2 + "\n")
            if not flag:
                os.write(fd, token1 + "," + token2 + "\n")
        lockfile.unlock(fd)
    
    def authenticate(self, json_data):
        if self.path == AUTH_PATH: #request is for dot1xforwarder
            if not (json_data.has_key("mac") and json_data.has_key("user")):
                self.send_error('Invalid form\n')
                return            
            
            #valid request format so new user has authenticated
            self.update_file(self.dot1x_active_file, json_data["mac"], json_data["user"])
            #self.write_to_file(self.dot1x_active_file, json_data["mac"], json_data["user"])
            self.send_signal(signal.SIGUSR1)
            message = "authenticated new client({}) at MAC: {}\n".format(json_data["user"], json_data["mac"]) 
        
        else: #request is for CapFlow
            if not (json_data.has_key("ip") and json_data.has_key("user")):
                self.send_error('Invalid form\n')
                return
            
            #valid request format so new user has authenticated
            self.update_file(self.capflow_file, json_data["ip"], json_data["user"])
            self.send_signal(signal.SIGUSR2)
            message = "authenticated new client({}) at IP: {}\n".format(json_data["user"], json_data["ip"]) 
        
        #write response 
        self._set_headers(200, 'text/html') 
        self.wfile.write(message)
        self.log_message("%s",message)
        
    def idle(self, json_data):
        if not (json_data.has_key("mac") and json_data.has_key("retrans")):
            self.send_error("Invalid form\n")
            return
        
        self.update_file(self.dot1x_idle_file, json_data["mac"], json_data["retrans"])
        self.send_signal(signal.SIGUSR1)
        self._set_headers(200, 'text/html')
        message = "Idle user on {} has been made to use captive portal after {} retransmissions\n".format(json_data["mac"], json_data["retrans"])
        self.log_message("%s",message)
        self.wfile.write(message)
        
    def deauthenticate(self, filename, unique_identifier, signal_type):
        fd = lockfile.lock(filename, os.O_APPEND | os.O_WRONLY)
        changed, to_write = self.read_file(filename, unique_identifier)
        
        if changed: #user has been deleted, update the file
            os.ftruncate(fd,0) #clear the file
            os.write(fd, to_write) 
        lockfile.unlock(fd)
        self.send_signal(signal_type)
        
        self._set_headers(200, 'text/html')
        message = "deauthenticated client at {} \n".format(unique_identifier)
        self.wfile.write(message)
        self.log_message("%s",message)

    def read_file(self,filename, unique_identifier):
        ''' Read a file and delete entries which contain the unique identifier
        
        :param filename: the name of the file
        :param unique_identifier: the entry which will be deleted
        :return: A tuple which contains a boolean of whether or not the unique 
        identifier was found, and the contents of the file without the unique
        identifier
        '''
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
        ''' Send a signal to the controller to indicate a change in config file
        
        :param signal_type: SIGUSR1 for dot1xforwarder, SIGUSR2 for CapFlow
        '''
        if self._contr_pid < 0: #has not looked up controller process ID yet
            for process in psutil.process_iter():
                if process.name() == "ryu-manager" and any("controller.py" in s for s in process.cmdline()):
                    self._contr_pid = process.pid
                    break
        os.kill(self._contr_pid,signal_type)  
    
    def check_if_json(self):
        try:
            ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        except:
            self.send_error("No content-type header\n")
            return None
            
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
        self.log_message("Error: %s", error)
        self.wfile.write(error) 
        
    do_GET = do_POST
        
    
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    pass
    
if __name__ == "__main__":
    server = ThreadedHTTPServer(('', 8080), HTTPHandler)
    print "starting server"
    server.serve_forever()
    
