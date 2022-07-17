import re, validators, os, socket, platform, concurrent.futures, requests
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

P_PORTS = [80, 443, 161, 631, 2501, 5001, 6310, 9100, 9101, 9102, 9600]
WEB_SERVER_PORTS = [22, 80, 443, 8080]
R_PORTS = [53, 80, 443]
    

def checkSingleFormat(device):

    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", device) or validators.url(device):
        return True
    return False


def checkRangeFormat(device):
    
    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$", device) or validators.url(device):
        return True
    return False


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

    possible_devices = {'Página web personal': 0, 'Router': 0, 'Impresora': 0}

    for port in total_open_ports:
        if port in WEB_SERVER_PORTS:
            possible_devices['Página web personal'] += 1
        if port in R_PORTS:
            possible_devices['Router'] += 1
        if port in P_PORTS:
            possible_devices['Impresora'] += 1

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

    return possible_devices


def analyzeHTTP(possible_devices, response):

    f = open('detection/diccs/web_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Página web personal'] += 1
    
    f = open('detection/diccs/router_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Router'] += 1
    
    f = open('detection/diccs/printer_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Impresora'] += 1

    return possible_devices


def create_table_html(data, detection):

    headers = ['Device', 'Open ports', 'Detected device']

    pre_existing_template="<!DOCTYPE html>" + "<html>" + "<head>" + "<style>"
    pre_existing_template+="table, th, td {border: 1px solid black;border-collapse: collapse;border-spacing:8px}"
    pre_existing_template+="</style>" + "</head>"
    pre_existing_template+="<body>" + "<strong>" + "REPORT DATE: " + detection.detection_date.strftime("%d-%b-%Y-%H-%M-%S") + "</strong>"
    pre_existing_template+="<br>"
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

    name=str(detection.id) + ".html"
    file = open('detection/templates/reports/' + name, "w")
    file.write(pre_existing_template)
    file.close()


def single_device_detection(device):

    res = {}

    device_name = device.name

    if not deviceActive(device_name):
        res['Not active'] = 'El dispositivo no está activo, por lo que no se puede detectar'
        return res
    
    temp_device = device_name
    total_open_ports = []

    if validators.url(temp_device):
        device_name = getIP(device_name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1,1000):
            executor.submit(scanPort, device_name, port, total_open_ports)

    if len(total_open_ports) > 0:

        probabilities = detectDevice(device_name, total_open_ports)
        max_probability = max(probabilities, key=probabilities.get)

        res['Open ports'] = ', '.join([str(p) for p in total_open_ports])
        res['Device type'] = max_probability
    
    else:
        res['No open ports'] = 'There are no open ports on device {}'.format(device_name)
        return res

    return res