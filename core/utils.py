import re, socket, validators, os, platform, requests, ipaddress
from pwn import log, sleep
import sys, concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
from datetime import datetime
import sqlite3

disable_warnings(InsecureRequestWarning)

PRINTER_PORTS = [80, 443, 161, 631, 2501, 5001, 6310, 9100, 9101, 9102, 9600]
WEB_SERVER_PORTS = [22, 80, 443, 8080]
ROUTER_PORTS = [53, 80, 443]


def usage():
    
    print("""\nUsage: python3 detection.py [options] target
    \nOptions (only one can be chosen):
    --help -> shows this help usage panel
    --single target -> performs a detection on a single device (IP or URL)
    --range target -> performs a detection on an IP range
    \nTarget format examples:
    - Single IP -> 192.168.0.1
    - URL -> http://www.example.com, https://example.es
    - IP range -> 192.168.0.0/24
    """)
    

def checkSingleFormat(device):

    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", device) or validators.url(device):
        return True
    return False


def checkRangeFormat(device):
    
    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$", device) or validators.url(device):
        return True
    return False


def createDatabase():

    if not os.path.exists('devices.db'):
        try:
            conn = sqlite3.connect('devices.db')
            conn.execute("""create table devices (
                    device text,
                    detection_date text,
                    open_ports text
            )""")
        except sqlite3.OperationalError:
            pass


def deviceInDatabase(device):

    try:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        cursor.execute('select * from devices where device = ?', (device,))

        data = cursor.fetchone()
        if data and len(data) > 0:
            return True
        return False

    except sqlite3.DatabaseError as e:
        print(e)
        sys.exit(1)


def removeDeviceFromDatabase(device):
    
    try:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        cursor.execute('delete from devices where device = ?', (device,))
        conn.close()
    except sqlite3.DatabaseError as e:
        print(e)
        sys.exit(1)


def saveDeviceInDatabase(device, detection_date, open_ports):

    try:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        cursor.execute("""insert into devices(device, detection_date, open_ports) 
                        values (?, ?, ?)""", (device, detection_date, str(open_ports)))
        conn.commit()
        conn.close()
    except sqlite3.DatabaseError as e:
        print(e)
        sys.exit(1)



def deviceActive(device):

    if validators.url(device):
        device = getIP(device)

    if platform.system().lower()=='windows':
        command = os.system('ping -n 1 {} >nul'.format(device))
    
    else:
        command = os.system('ping -c 1 {} > /dev/null'.format(device))
        
    return command == 0


def getIP(device):

    if device.startswith('https://www'):
        if device[-1] == '/':
            device = device[:-1]
        return socket.gethostbyname(device[12:])
    elif device.startswith('http://www'):
        if device[-1] == '/':
            device = device[:-1]
        return socket.gethostbyname(device[11:])
    elif device.startswith('https') and 'www' not in device:
        if device[-1] == '/':
            device = device[:-1]
        return socket.gethostbyname(device[8:])
    elif device.startswith('http') and 'www' not in device:
        if device[-1] == '/':
            device = device[:-1]
        return socket.gethostbyname(device[7:])
    return socket.gethostbyname(device[7:])


def scanPort(device, port, total_open_ports):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((device, port))
        s.close()
        total_open_ports.append(port)
    except:
        pass


def detectPorts(total_open_ports):

    possible_devices = {'Personal web server': 0, 'Router': 0, 'Printer': 0}

    for port in total_open_ports:
        if port in WEB_SERVER_PORTS:
            possible_devices['Personal web server'] += 1
        if port in ROUTER_PORTS:
            possible_devices['Router'] += 1
        if port in PRINTER_PORTS:
            possible_devices['Printer'] += 1

    return possible_devices


def detectServices(device, total_open_ports, possible_devices):

    if not validators.url(device):
        device = 'http://' + device

    if 80 in total_open_ports:
        response = requests.get(device, verify=False).text.lower()
        possible_devices = analyzeHTTP(possible_devices, response)

    return possible_devices


def detectDevice(device, total_open_ports):

    possible_devices = detectPorts(total_open_ports)
    possible_devices = detectServices(device, total_open_ports, possible_devices)

    #print('\nResultado final: ' + str(possible_devices))

    return possible_devices


def analyzeHTTP(possible_devices, response):

    f = open('diccs/web_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Personal web server'] += 1
    
    f = open('diccs/router_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Router'] += 1
    
    f = open('diccs/printer_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Printer'] += 1

    return possible_devices


def create_table_html(data):

    headers = ['Device', 'Open ports', 'Detected device']

    pre_existing_template="<!DOCTYPE html>" + "<html>" + "<head>" + "<style>"
    pre_existing_template+="table, th, td {border: 1px solid black;border-collapse: collapse;border-spacing:8px}"
    pre_existing_template+="</style>" + "</head>"
    pre_existing_template+="<body>" + "<strong>" + "REPORT DATE: " + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + "</strong>" 
    pre_existing_template+="<table style='width:50%'>"
    pre_existing_template+='<tr>'
    for header_name in headers:
        pre_existing_template+="<th style='background-color:#3DBBDB;width:85;color:white'>" + header_name + "</th>"
    pre_existing_template+="</tr>"
    
    sub_template="<tr style='text-align:center'>"
    sub_template+="<td>" + str(data[0]) + "</td>"
    sub_template+="<td>" + str(data[1]) + "</td>"
    sub_template+="<td>" + str(data[2]) + "</td>"
    sub_template+="<tr/>"
    pre_existing_template+=sub_template
    pre_existing_template+="</table>" + "</body>" + "</html>"

    name=str(datetime.today().strftime("%d-%b-%Y-%H-%M-%S"))+".html"
    file = open('reports/' + name, "w")
    file.write(pre_existing_template)
    file.close()


def singleDeviceDetection(single_device):
    print('')
    p1 = log.progress('')
    p1.status('Checking if the device {} is active'.format(single_device))
    sleep(2)

    if not deviceActive(single_device):
        p1.failure('Device {} is not active'.format(single_device))
        sys.exit(1)
    
    p1.success('Device {} is active'.format(single_device))
    sleep(1)

    print('')
    p2 = log.progress('')
    p2.status('Starting port scanning on ' + single_device)
    sleep(2)
    
    device = single_device
    total_open_ports = []

    if validators.url(single_device):
        device = getIP(device)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1,1000):
            executor.submit(scanPort, device, port, total_open_ports)

    if len(total_open_ports) > 0:
        p2.success('Port scanning finished on {}, open ports are '.format(single_device) + ', '.join([str(p) for p in total_open_ports]))
        sleep(1)

        print('')
        p3 = log.progress('')
        p3.status('Detecting device {} (router, personal web server or printer)'.format(single_device))
        sleep(2)

        probabilities = detectDevice(single_device, total_open_ports)
        max_probability = max(probabilities, key=probabilities.get)
        p3.success('Device {} is a {}'.format(single_device, max_probability.lower()))
        
        detection_date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        saveDeviceInDatabase(single_device, detection_date, total_open_ports)

        create_table_html([single_device, ', '.join([str(p) for p in total_open_ports]), max_probability])
        sys.exit(0)
    
    else:
        p2.failure('There are no open ports on device {}'.format(single_device))
        sys.exit(1)


def multipleDevicesDetection(ip_range):

    for ip in ipaddress.IPv4Network(ip_range):
        ip = str(ip)
        print('')
        p1 = log.progress('')
        p1.status('Checking if the device {} is active'.format(ip))
        sleep(2)

        if not deviceActive(ip):
            p1.failure('Device {} is not active'.format(ip))
            continue
        
        p1.success('Device {} is active'.format(ip))
        sleep(1)

        print('')
        p2 = log.progress('')
        p2.status('Starting port scanning on ' + ip)
        sleep(2)
        
        device = ip
        total_open_ports = []

        if validators.url(ip):
            device = getIP(device)

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            for port in range(1,1000):
                executor.submit(scanPort, device, port, total_open_ports)

        if len(total_open_ports) > 0:
            p2.success('Port scanning finished on device {}, open ports are '.format(ip) + ', '.join([str(p) for p in total_open_ports]))
            sleep(1)

            print('')
            p3 = log.progress('')
            p3.status('Detecting device {} (router, personal web server or printer)'.format(ip))
            sleep(2)

            probabilities = detectDevice(device, total_open_ports)
            print(str(probabilities))
            max_probability = max(probabilities, key=probabilities.get)
            p3.success('Device {} is a {}'.format(ip, max_probability.lower()))

            detection_date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            saveDeviceInDatabase(device, detection_date, total_open_ports)
            continue
        
        else:
            p2.failure('There are no open ports on device {}'.format(ip))
            continue
