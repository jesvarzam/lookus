import re, validators, socket, concurrent.futures, requests, subprocess
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

PRINTER_PORTS = [80, 443, 161, 631, 2501, 5001, 6310, 9100, 9101, 9102, 9600]
WEB_SERVER_PORTS = [22, 80, 443, 8080]
ROUTER_PORTS = [22, 53, 80, 443]
CAMERA_PORTS = [80, 443, 554]
    

def checkSingleFormat(device):

    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", device) or validators.url(device):
        return True
    return False


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

    possible_devices = {'Página web personal': 0, 'Router': 0, 'Impresora': 0, 'Cámara': 0}

    for port in total_open_ports:
        if port in WEB_SERVER_PORTS:
            possible_devices['Página web personal'] += 1
        if port in ROUTER_PORTS:
            possible_devices['Router'] += 1
        if port in PRINTER_PORTS:
            possible_devices['Impresora'] += 1
        if port in CAMERA_PORTS:
            possible_devices['Cámara'] += 1

    return possible_devices


def detectServices(device, total_open_ports, possible_devices):

    
    if 80 in total_open_ports:

        http_device = device

        if not validators.url(device):
            http_device = 'http://' + device

        response = requests.get(http_device, verify=False).text.lower()
        output = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
        output = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', output).lower()
        response+=output
        possible_devices = analyzeHTTP(possible_devices, response)

    if 443 in total_open_ports:

        https_device = device

        if not validators.url(device):
            https_device = 'https://' + device

        response = requests.get(https_device, verify=False).text.lower()
        output = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
        output = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', output).lower()
        response+=output
        possible_devices = analyzeHTTPS(possible_devices, response)

    return possible_devices


def detectBrands(device, possible_devices):

    http_device = device

    if not validators.url(device):
            http_device = 'http://' + device

    response = requests.get(http_device, verify=False).text.lower()
    output = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
    output = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', output).lower()
    response+=output

    f = open('detection/diccs/camera_brands.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Cámara'] += 3

    f = open('detection/diccs/printer_brands.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Impresora'] += 3

    f = open('detection/diccs/cms_brands.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Página web personal'] += 3


    return possible_devices


def detectDevice(device, total_open_ports):

    possible_devices = detectPorts(total_open_ports)
    possible_devices = detectServices(device, total_open_ports, possible_devices)
    possible_devices = detectBrands(device, possible_devices)

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

    f = open('detection/diccs/camera_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Cámara'] += 1

    return possible_devices


def analyzeHTTPS(possible_devices, response):

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

    f = open('detection/diccs/camera_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Cámara'] += 1

    return possible_devices


def create_table_html(data, detection):

    headers = ['Dispositivo', 'Puertos abiertos', 'Dispositivo detectado', 'Cabeceras HTTP']

    template="<!DOCTYPE html>" + "<html>" + "<head>" + "<meta charset='UTF-8'>" + "<style>"
    template+="table, th, td {border: 1px solid black;border-collapse: collapse;border-spacing: 15px;padding: 10px; margin-top: 20px}"
    template+="</style>" + "</head>"
    template+="<body>" + "<strong>" + "Fecha de detección: " + detection.detection_date.strftime("%d-%b-%Y-%H-%M-%S") + "</strong>"
    template+="<table style='width:50%'>"
    template+='<tr>'
    template+="<th style='background-color:#3DBBDB;width:85;color:white'>" + headers[0] + "</th>"
    template+="</tr>"
    template+="<tr style='text-align:center'>"
    template+="<td>" + str(data[0]) + " (" + str(data[2]) + ") " + "</td>"
    template+="</tr>"
    template+="</table>"
    template+="<table style='width:50%'>"
    template+='<tr>'
    template+="<th style='background-color:#3DBBDB;width:85;color:white'>" + headers[1] + "</th>"
    template+="</tr>"
    template+="<tr style='text-align:center'>"
    template+="<td>" + str(data[1]) + "</td>"
    template+="</tr>"
    template+="</table>"
    template+="<table style='width:50%'>"
    template+='<tr>'
    template+="<th style='background-color:#3DBBDB;width:85;color:white'>" + headers[3] + "</th>"
    template+="</tr>"

    if data[3] == 'No es posible obtener información':
        template+="<tr style='text-align:center'>"
        template+="<td>" + str(data[3]) + "</td>"
        template+="</tr>"
    
    else:
        for http_info in data[3]:
            template+="<tr style='text-align:center'>"
            template+="<td>" + str(http_info) + "</td>"
            template+="</tr>"

    template+="</table>"
    template_pdf="<form style='margin-top: 20px' action='/detection/pdf/{}'>".format(str(detection.id)) + "<input type='submit' value='Exportar a PDF' />" + "</form>"
    template+="</body>" + "</html>"

    name1=str(detection.id) + ".html"
    file1 = open('detection/templates/reports/' + name1, "w")
    file1.write(template + template_pdf + "</body>" + "</html>")
    file1.close()

    name2=str(detection.id) + "pdf.html"
    file2 = open('detection/templates/reports/' + name2, "w")
    file2.write(template + "</body>" + "</html>")
    file2.close()


def single_device_detection(device):

    res = {}

    device_name = device.name
    
    total_open_ports = []
    device_name_port_scan = device.name

    if validators.url(device_name):
        device_name_port_scan = getIP(device_name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1,1000):
            executor.submit(scanPort, device_name_port_scan, port, total_open_ports)

    if len(total_open_ports) > 0:

        probabilities = detectDevice(device_name, total_open_ports)
        print(probabilities)
        max_probability = max(probabilities, key=probabilities.get)

        res['Open ports'] = ', '.join([str(p) for p in total_open_ports])
        res['Device type'] = max_probability
    
    else:
        res['No open ports'] = 1
        return res

    return res