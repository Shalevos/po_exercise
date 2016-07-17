import codecs

import cherrypy
from AESCipher import AESCipher
import os
import sqlite3
import ipaddress
from binascii import unhexlify
import traceback

DB_STRING = "my.db"


def set_user_ip(user, password, ip):
    """
    Set the ip of a user
    """
    with sqlite3.connect(DB_STRING) as con:
        con.execute("UPDATE users SET ip = ? WHERE user = ? AND password = ? AND ip IS NULL ", (ip, user, password))


def check_credentials(user, password):
    """
    Check the credentials of a user
    """
    with sqlite3.connect(DB_STRING) as con:
        result = con.execute("SELECT * FROM users WHERE user = ? AND password = ? ", (user, password)).fetchone()
        print(str(result))
        return result


def check_cookie_credentials(user, password, ip):
    """
    Check the credentials of a cookie (including ip)
    """
    with sqlite3.connect(DB_STRING) as con:
        result = con.execute("SELECT * FROM users WHERE user = ? AND password = ? AND ip = ? ", (user, password, ip)).fetchone()
        print(str(result))
        return result


def ip2bytes(ip4str):
    """
    Convert an ip string ('127.0.0.1') to a 128-bit block of bytes
    """
    ip4 = ipaddress.IPv4Address(ip4str)
    hex_ip = str(hex(int(ip4)))[2:] + '00'*12
    hex_ip = unhexlify(hex_ip)
    return hex_ip


class CookieParseError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Server(object):
    key = "140b41b22a29beb4061bda66b6747e14"
    cryptmaster = AESCipher(key)

    def decrypt_cookie(self, enc_cookie):
        try:
            plaintext = self.cryptmaster.decrypt(enc_cookie)
            if plaintext == False:
                return False, None, None
            ip = '.'.join(str(plaintext[i]) for i in range(4))
            cookie = str(plaintext[16:])[2:-1]
            user = cookie.split('|')[0]
            password = cookie.split('|')[1]
            return ip, user, password
        except:
            raise CookieParseError("Cannot parse cookie!")

    def encrypt_cookie(self, ip, user, password):
        ip = ip2bytes(ip)
        plaintext = user + "|" + password
        plaintext = bytes(plaintext, "utf8")
        plaintext = ip + plaintext
        return self.cryptmaster.encrypt(plaintext)

    @cherrypy.expose
    def index(self):
        try:
            cookie = cherrypy.request.cookie
            ip, user, password = self.decrypt_cookie(cookie['topsecret'].value[2:-1])
            if ip == False:
                return "incorrect padding"
            print("The creds are: ip - " + ip + " - user - " + user + " - pass - " + password)
            if ip != cherrypy.request.remote.ip:
                print("incorrect ip: " + cherrypy.request.remote.ip + " instead of: " + ip)
                return "incorrect username/password"
            if check_cookie_credentials(user, password, ip):
                return "login successful"
            return "incorrect username/password"
        except CookieParseError as e:
            return e.value
        except Exception as e:
            traceback.print_exc()
            return open("form.html")

    @cherrypy.expose
    def login(self, user="", password=""):
        ip = cherrypy.request.remote.ip
        print("the ip: " + str(ip))
        if check_credentials(user, password):
            cookie = cherrypy.response.cookie
            ciphertext = self.encrypt_cookie(ip, user, password)
            cookie['topsecret'] = ciphertext

            set_user_ip(user, password, ip)
            return "login success<br \>You are: " + user + "<br \> Your password: " + password
        return "login failed!<br \>You are: " + user + "<br \> Your password: " + password

    @cherrypy.expose
    def register(self, user="", password="", reg_pass=""):
        if user == "" or password == "" or reg_pass == "":
            return open("registration.html")

        if '|' in user or '|' in password:
            return "'|' is a forbidden character!"

        if reg_pass == "biucrypto":
            with sqlite3.connect(DB_STRING) as con:
                con.execute('INSERT INTO users (user, password) VALUES (?, ?)', (user, password))
            return "registration successful"
        else:
            return "registration failed"


"""if __name__ == '__main__':
    s = Server()
    ip = "127.134.64.2"
    user = "shalev"
    password = "123456"
    rip, ruser, rpass = s.decrypt_cookie("d84874dbc3c92ac242243f8d01d5cb54c1b21abb5daa4b98b318ec2c7b857e26ebafbf1cfe13a764109c0de6c9ebb7a8")
    print("ip: " + rip + "\nuser: " + ruser + "\npass: " + rpass)

    e = s.encrypt_cookie(ip, user, password)
    print(e)
    rip,ruser,rpass = s.decrypt_cookie(e)
    print("ip: " + rip + "\nuser: " + ruser + "\npass: " + rpass)"""


if __name__ == '__main__':

    if None:
        print("in")
    else:
        print("out")
    conf = {
        '/': {
            'tools.staticdir.root': os.path.abspath(os.getcwd())
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': './public'
        }
    }
    cherrypy.config.update({'server.socket_host': '127.0.0.1',
                                                  'server.socket_port': 8080, 'engine.autoreload_on': False
    })
    cherrypy.quickstart(Server(), '/', conf)
