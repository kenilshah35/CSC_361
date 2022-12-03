import sys
import socket
import ssl
from urllib.parse import urlparse


def checkHTTPS(url):

    urlFinal = url
    https = True
    domain = url.netloc

    #Create a ssl context and wrap the socket in said context
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    sock = ctx.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname = domain )

    #print("\n****CHECKING FOR HTTPS SUPPORT****\n")

    #try connecting to port 443 to check if https actually supported
    try:
        try:
            sock.connect((domain, 443))
        except socket.gaierror:
            print("Invalid URL")
            sys.exit(1)

        sock.close()
        #print("         HTTPS SUPPORT FOUND!!\n\n")
        return urlFinal, https

    #exception implies https not supported
    except ssl.SSLError:
        sock.close()
        urlFinal = url._replace(scheme="http")
        https = False
        #print("         HTTPS SUPPORT NOT FOUND!!\n\n")
        return urlFinal, https

def checkHTTPver(url):

    domain = url.netloc
    http1 = False
    port = 443
    if url.scheme == "http":
        port = 80

    #Create a ssl context and wrap the socket in said context
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    sock = ctx.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname = domain )

    #print("\n****CHECKING FOR HTTP/1.1 SUPPORT****\n")

    #Connecting to host
    sock.connect((domain, port))

    #Sending a GET request
    sock.send("GET / HTTP/1.1\r\nhost: {}\r\nconnection: keep-alive\r\n\r\n".format(domain).encode())

    #Receiving data from server
    data = sock.recv(10000).decode(errors='ignore')
    sock.close()

    #Splitting received data into response header and response body
    splitData = data.split('\r\n\r\n')
    head = splitData[0]

    #Splitting header to find http ver., status code
    splitHead = head.split('\r\n')

    httpVersion = splitHead[0].split(' ')[0]
    statusCode =  splitHead[0].split(' ')[1]

    if statusCode == "301" or statusCode == "302":
          #print("\n****STATUS CODE 301 or 302 FOUND RESTARTING WITH NEW URL****\n")
          for line in splitHead[1:]:
              #find the location of the new website
              if line.startswith("Location"):
                  location = line.split(': ')[1]
                  location = urlparse(location)
                  if location.scheme == '':
                      location = location._replace(scheme="https")

                  #Recall both functions with the new URL
                  urlNew, https = checkHTTPS(location)
                  http1, head, url = checkHTTPver(urlNew)
                  #Determine the http Version
                  if http1 == True:
                      httpVersion == "HTTP/1.1"
    elif statusCode == "404":
        print("Error: 404 not found")
        sys.exit(1)

    if httpVersion == "HTTP/1.1":
        http1 = True
        #print("         HTTP/1.1 SUPPORT FOUND!!\n\n")

    return http1, head, url


def collectCookies(head):
    cookies = []
    splitHead = head.split('\r\n')

    #Consider each line in response starting from the second line
    for line in splitHead[1:]:
        if line.startswith('Set-Cookie: '):
            splitLine = line.split(': ')
            #Seperate each Cookie attribute
            attributes = splitLine[1].split('; ')

            cookieName = attributes[0].split('=')[0]
            cookieValue = attributes[0].split('=')[1]

            expireTime = None
            domainName = None

            for attribute in attributes:
                if "expires" in attribute:
                    expireTime = attribute.split('=')[1]
                if "domain" in attribute:
                    domainName = attribute.split('=')[1]

            #Store in cookies as a dictionary
            cookies.append({'cookie-name' : cookieName, 'cookie-value': cookieValue, 'expire-time' : expireTime, 'domain-name' : domainName})

    return cookies

def checkHTTP2(url):

    http2 = False
    domain = url.netloc
    port = 443
    if url.scheme == "http":
        port = 80

    #Creating a context and wrapping the socket + Setting alpn protocols to test http2 support
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    ctx.check_hostname = False
    sock = ctx.wrap_socket( socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname = domain )

    try:
        try:
            sock.connect((domain, port))
        except socket.gaierror:
            print("Invalid URL")
            sys.exit(1)

    except ssl.SSLError:
        #print("HTTP2 not supported as HTTPS is not supported")
        http2 = False

    #If connection through http2 protocol then support for http2 confirmed
    if sock.selected_alpn_protocol() == 'h2':
        http2 = True
    else:
        http2 = False

    sock.close()

    return http2

def printSolution(url, https, http1, http2, cookies, header):

    print("---Response Header---\n{}\n\n".format(header))

    print("website: {}".format(url.netloc))

    print("1. Supports of HTTPS: {}".format("yes" if https else "no"))

    print("2. Supports of HTTP/1.1: {}".format("yes" if http1 else "no"))

    print("3. Supports http2: {}".format("yes" if http2 else "no"))

    print("4. List of Cookies:")

    if cookies is not None:
        for cookie in cookies:
            print("cookie name: {}, cookie value: {}, expires time: {}, domain name: {}".format(cookie['cookie-name'], cookie['cookie-value'], cookie['expire-time'], cookie['domain-name']))
    else:
        print("No Cookies Found")

def main():
    #Testing if any input entered
    try:
        if sys.argv[1] is None:
            print("URL required")
        else:
            url = sys.argv[1]
    except:
        print("error exiting")
        sys.exit(1)

    #Testing if the url entered is Valid
    try:
        test_url = urlparse(url)
    except:
        print("Invalid URL!")

    if test_url.scheme == '':
        parsedURL = urlparse("https://{}".format(url))
    else:
        parsedURL = test_url

    httpsFlag = False
    http1Flag = False
    http2Flag = False
    cookies = [] #List of Dictionaries

    #Check support for HTTPS
    parsedURL, httpsFlag = checkHTTPS(parsedURL)

    #Check support for HTTP/1.1
    http1Flag, header, parsedURL  = checkHTTPver(parsedURL)

    #Collect cookies
    cookies = collectCookies(header)

    #Check support for HTTP2
    http2Flag = checkHTTP2(parsedURL)

    #Print out the solution
    printSolution(parsedURL, httpsFlag, http1Flag, http2Flag, cookies, header)

if __name__ == "__main__":
    main()
