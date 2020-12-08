from socket import *        #socket networking
import sys                  #args handling
import re                   #regular expressions

def DictFromList(data):
    address = []
    type_ = []
    j = 0
    result = dict()
    for i in data:
        #if :ptr / :A missing
        try:
            addressItem, typeItem = i.split(":")
        except:
            addressItem = i
            typeItem = "0"
        #2 same keys cant be in dictionary
        if addressItem in address:
            addressItem += str(j) + "DELME"
            address.append(addressItem)
            j+=1
        else:    
            address.append(addressItem)
        type_.append(typeItem)
    result = dict(zip(address,type_))
    return result

def portValidity():
    argc = len(sys.argv)
    if argc < 2:
        return False
    else:
        port = sys.argv[1]
    
    if port.isdigit():
        return True
    else:
        return False

def ipv4Validity(address):
    if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",address):
        return True
    else:
        return False

def HTTPheader(data, response, request):
    
    if request is 'GET':
        data += "HTTP/1.1 "
        if response is 'OK':
            data += "200 OK\r\n\r\n" 
            return data
        elif response is 'BAD':
            data += "400 Bad Request\r\n\r\n"
            return data
        elif response is 'Method':
            data += "405 Method Not Allowed\r\n\r\n"
            return data  
        elif response is 'NotFound':
            data += "404 Not Found\r\n\r\n"
            return data
        elif response is 'Internal':
            data += "500 Internal Server Error\r\n\r\n"
            return data
        else:
            data += "500 Internal Server Error\r\n\r\n"
            return data
    elif request is 'POST':
        if response is 'OK':
            temp = "HTTP/1.1 200 OK \r\n\r\n"
            temp += data
            return temp
        elif response is 'BAD':
            temp = "HTTP/1.1 400 Bad Request \r\n\r\n"
            temp += data
            return temp
        elif response is 'Method':
            temp = "405 Method Not Allowed\r\n\r\n"
            temp += data
            return temp  
        elif response is 'NotFound':
            temp = "404 Not Found\r\n\r\n"
            temp += data
            return temp
        elif response is 'Internal':
            temp = "500 Internal Server Error\r\n\r\n"
            temp += data
            return temp


def createServer():
    socketServer = socket(AF_INET, SOCK_STREAM)
    try:
        socketServer.bind(("localhost", int(sys.argv[1])))
        socketServer.listen(5)

        while(1):
            #---Variables for error handling---#
            resolve = False
            dns_query = False
            bad_post = 0
            data = ""
            #dns_query = True
            ok_post = 0
            delme = False

            (clientsocket, adress) = socketServer.accept()
            read = clientsocket.recv(5000).decode()
            pieces = read.split()
            #---GET REQUEST sending data and translating Host to IPv4---#
            for i in pieces:
                #---GET METHOD---#
                if "/resolve?" in i:
                    resolve = True
                    #adressNtype =list( www.xxx.xxx, type=..)"""
                    addressNtype = i.split("=")
                    address = addressNtype[1]#www.google.com&type
                    address = address[:-5] #www.google.com
                    type_ = addressNtype[2]
                    #---Adress or PTR---#
                    if type_ == 'A':
                        try:
                            ip = gethostbyname(address)
                            if ipv4Validity(address):#given hostname is ip
                            	data += HTTPheader(data, 'BAD', 'GET')
                            	continue
                            data += HTTPheader(data, 'OK', 'GET')
                        except:
                            data += HTTPheader(data, 'NotFound', 'GET')
                            continue
                        data+=address + ":" + type_ + "=" + ip #www.google.com:A=123.456.78.9
                        data+="\r\n"
                    elif type_ == 'PTR':
                        #---hostname given to PTR---#
                        if not ipv4Validity(address):   #given string is not IPv4 format
                            data += HTTPheader(data, 'BAD', 'GET')
                            #data+=address + ":" + type_ + "=" + address + "\r\n" 172.217.23.196 = 172.217.23.196 WRONG
                            continue
                        try:
                            domain_ = gethostbyaddr(address) #tuple(3)
                            data += HTTPheader(data, 'OK', 'GET')
                        except:
                            data += HTTPheader(data, 'NotFound', 'GET')
                            continue
                        domain = ''.join(domain_[0])
                        data+=address + ":" + type_ + "=" + domain #123.34.5.6:PTR=www.google.com
                        data+="\r\n"
                    #---Neither A or PTR type is used---#
                    else: 
                        data += HTTPheader(data, 'BAD', 'GET')
                        break

                #---POST METHOD---#
                elif "/dns-query" in i:
                    dns_query = True
                    if not("/dns-query" == i[-10:]):
                        data += HTTPheader(data,'BAD', 'GET')
                        break

                    del pieces[:13]#first 13 is garbage
                    postAddresses = pieces
                    postAddressesDict = DictFromList(postAddresses)#create dictionary for better access
                    
                    #---TYPE of action---#

                    for j in postAddressesDict:
                        #copy dict handling
                        #:PTR and :A missing
                        if 'PTR' not in postAddressesDict[j] and 'A' not in postAddressesDict[j] and bad_post is 0:
                            bad_post = 1
                        #multiple requests with same body
                        if 'DELME' in j:
                            delme = True
                        
                        if delme:
                            j = j[:-6]
                            delme = False

                        if 'A' == postAddressesDict[j]:
                            if ipv4Validity(j):   #given string is IPv4 format -- trying to translate address from address
                                bad_post = 1
                                continue
                            try:
                                if ok_post is 0:
                                    ok_post = 1
                                ip = gethostbyname(j) #tuple(3)
                            except: 
                                if bad_post is 0:
                                    bad_post = 1
                                continue
                            data+=j + ":" + postAddressesDict[j] + "=" + ip #www.google.com:A=123.456.78.9
                            data+="\r\n"
                        elif 'PTR' == postAddressesDict[j]:
                            if not ipv4Validity(j):   #given string is not IPv4 format -- trying to translate pointer from address
                                bad_post = 1
                                continue
                            try:
                                if ok_post is 0:
                                    ok_post = 1
                                domain_ = gethostbyaddr(j)
                            except:
                                if bad_post is 0:
                                    bad_post = 1
                                continue

                            domain_ = gethostbyaddr(j) 
                            domain = ''.join(domain_[0])
                            data+=j + ":" + postAddressesDict[j] + "=" + domain #123.34.5.6:PTR=www.google.com
                            data+="\r\n"
                        #NEITHER A or PTR
                        elif "0" == postAddressesDict[j]:
                            if bad_post is 0:
                                bad_post = 1
                                continue
                            continue


                elif (not resolve and not dns_query and (i == pieces[1])):
                    #---Neither get or post is used---#
                       data += HTTPheader(data, 'Method', 'GET') 
    
            #----POST METHOD HEADER HANDLING----#
            if (bad_post is 0) and (ok_post is 1):
                data = HTTPheader(data, 'OK', 'POST')
            elif (bad_post is 1):
                data = HTTPheader(data, 'BAD', 'POST')

            clientsocket.sendall(data.encode())
            clientsocket.shutdown(SHUT_WR)
    #---Interrupts handling---#
    except KeyboardInterrupt :
        print("\nShutting down .. \n")
    except Exception as exc:
        print(exc)
    
    socketServer.close()



#-----------MAIN -----------#
if portValidity():
    createServer()
else:
    print("ERROR: Invalid input PORT(empty or wrong format)."); 
