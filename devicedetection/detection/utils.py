import re, validators, socket, requests, subprocess, ipaddress, nmap, os
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
disable_warnings(InsecureRequestWarning)

PRINTER_PORTS = [80, 443, 161, 631, 2501, 5001, 6310, 9100, 9101, 9102, 9600]
WEB_SERVER_PORTS = [22, 80, 443, 8080]
ROUTER_PORTS = [22, 53, 80, 443]
CAMERA_PORTS = [80, 443, 554]

PRINTER_KEYWORDS = ['printer', 'impresora']
ROUTER_KEYWORDS = ['router', 'gateway']
CAMERA_KEYWORDS = ['cámara', 'camera']

TOTAL = 81

def return_response(device):
    http_device = device

    if not validators.url(device):
        http_device = 'http://' + device
    
    try:
        response = requests.get(http_device, verify=False, timeout=10).text.lower()
    except:
        response = ''
    whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
    whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
    if check_redirects(whatweb):
        http_device = follow_redirect(whatweb)
        response = requests.get(http_device, verify=False).text.lower()
        whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
        whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
        response+=whatweb
    
    return response


def train_devices(devices, user):

    folder = str(user.username) + str(user.id)
    if not os.path.exists('detection/diccs/' + folder):
        os.mkdir('detection/diccs/' + folder)
        os.system('cp detection/diccs/*_dicc.txt detection/diccs/' + folder)
    
    for d in devices:
        
        f = open('detection/diccs/' + folder + '/' + d, 'a')

        for device in devices[d]:

            device = device.strip()
            if device == '':
                continue

            if check_port_http(device):

                response = return_response(device)
                f.write('\n' + response)
        
        f.close()

    
def check_port_http(device):

    device_name_port_scan = device

    if validators.url(device):
        device_name_port_scan = getIP(device)
    
    nm = nmap.PortScanner()
    port_scan = nm.scan(device_name_port_scan, arguments='-p80,443 -sS --min-rate 5000 -n -Pn')['scan'][device_name_port_scan]['tcp']

    if port_scan[80]['state'] == 'closed' and port_scan[443]['state'] == 'closed':
        return False
    
    return True


def checkSingleFormat(device):

    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", device) or validators.url(device):
        return True
    return False


def checkRangeFormat(device):
    
    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$", device):
        return True
    return False


def get_single_format(device):
    if re.search(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", device):
        return 'Dirección IP'
    return 'Dirección URL'


def check_redirects(whatweb):

    headers = whatweb.split('\n')
    print(headers)
    for h in headers:

        if '302 found' in h:
            return True

    return False


def follow_redirect(whatweb):

    headers = whatweb.split('\n')
    for h in headers:

        if '302 found' in h:
            print(h.split(' ')[0])
            return str(h.split(' ')[0])


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


def detectBrands(possible_devices, response):

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


def check_keywords(possible_devices, response):

    for keyword in PRINTER_KEYWORDS:
        if keyword in response:
            print('Palabra de printer keyword encontrada: ' + keyword)
            possible_devices['Impresora'] += 3
    
    for keyword in ROUTER_KEYWORDS:
        if keyword in response:
            print('Palabra de router keyword encontrada: ' + keyword)
            possible_devices['Router'] += 3
    
    for keyword in CAMERA_KEYWORDS:
        if keyword in response:
            print('Palabra de cámara keyword encontrada: ' + keyword)
            possible_devices['Cámara'] += 3

    return possible_devices


def analyze_response(possible_devices, response, user, use_own_dicc):

    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/web_dicc.txt')
    else: f = open('detection/diccs/web_dicc.txt')
    for line in f:
        if line.strip() in response:
            print('Palabra de web encontrada: ' + line.strip())
            possible_devices['Página web personal'] += 1
    
    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/router_dicc.txt')
    else: f = open('detection/diccs/router_dicc.txt')
    for line in f:
        if line.strip() in response:
            print('Palabra de router encontrada: ' + line.strip())
            possible_devices['Router'] += 1
    
    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/printer_dicc.txt')
    else: f = open('detection/diccs/printer_dicc.txt')
    for line in f:
        if line.strip() in response:
            print('Palabra de printer encontrada: ' + line.strip())
            possible_devices['Impresora'] += 1

    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/camera_dicc.txt')
    else: f = open('detection/diccs/camera_dicc.txt')
    for line in f:
        if line.strip() in response:
            print('Palabra de camera encontrada: ' + line.strip())
            possible_devices['Cámara'] += 1

    return possible_devices


def detectDevice(total_open_ports, response, user, use_own_dicc):

    possible_devices = detectPorts(total_open_ports)
    possible_devices = detectBrands(possible_devices, response)
    possible_devices = check_keywords(possible_devices, response)
    possible_devices = analyze_response(possible_devices, response, user, use_own_dicc)
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

    if data[3] == 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información':
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


def single_device_detection(device, user, use_own_dicc):

    res = {}

    device_name = device.name
    device_name_port_scan = device.name
    device_format = 'IP'

    if validators.url(device_name):
        device_format = 'URL'
        device_name_port_scan = getIP(device_name)

    total_open_ports = []

    nm = nmap.PortScanner()
    port_scan = nm.scan(device_name_port_scan, arguments='-p- --open -sS --min-rate 5000 -n -Pn')['scan']
    if device_name_port_scan in port_scan.keys():
        total_open_ports = [*port_scan[device_name_port_scan]['tcp'].keys()]

    if len(total_open_ports) > 0:

        full_response = ''
        whatweb = ''

        if (80 in total_open_ports or 443 in total_open_ports) and device_format == 'URL':
            response = requests.get(device_name, verify=False).text.lower()
            whatweb = subprocess.run(['whatweb', device_name], stdout=subprocess.PIPE).stdout.decode('utf-8')
            whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
            if check_redirects(whatweb):
                device_name = follow_redirect(whatweb)
                response = requests.get(device_name, verify=False).text.lower()
                whatweb = subprocess.run(['whatweb', device_name], stdout=subprocess.PIPE).stdout.decode('utf-8')
                whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
            full_response = response + whatweb
        
        elif 80 in total_open_ports and device_format == 'IP':
            http_device = 'http://' + device_name
            response = requests.get(http_device, verify=False).text.lower()
            whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
            whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
            if check_redirects(whatweb):
                http_device = follow_redirect(whatweb)
                print(http_device)
                response = requests.get(http_device, verify=False).text.lower()
                whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
                whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
            full_response = response + whatweb

        elif 443 in total_open_ports and device_format == 'IP':
            http_device = 'https://' + device_name
            response = requests.get(http_device, verify=False).text.lower()
            whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
            whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
            if check_redirects(whatweb):
                http_device = follow_redirect(whatweb)
                print(http_device)
                response = requests.get(http_device, verify=False).text.lower()
                whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
                whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
            full_response = response + whatweb

        if full_response!='':
            print(full_response)
            probabilities = detectDevice(total_open_ports, full_response, user, use_own_dicc)
            max_probability = max(probabilities)
            factor = 1.0/sum(probabilities.values())
            for p in probabilities:
                probabilities[p] = probabilities[p]*factor*100.00
            max_probability = max(probabilities)
            res['Open ports'] = ', '.join([str(p) for p in total_open_ports])
            res['Device type'] = max_probability
            res['Response'] = response
            res['Whatweb'] = whatweb

        else:
            probabilities = detectPorts(total_open_ports)
            max_probability = max(probabilities, key=probabilities.get)
            res['Open ports'] = ', '.join([str(p) for p in total_open_ports])
            res['Device type'] = max_probability
    
    else:
        res['No open ports'] = 1

    return res


def range_device_detection(range_device, user, use_own_dicc):

    res = []

    for device in ipaddress.IPv4Network(range_device.name):

        device = str(device)

        detection = {}
        detection['Device'] = device

        device_name_port_scan = device
        device_format = 'IP'

        if validators.url(device):
            device_format = 'URL'
            device_name_port_scan = getIP(device)

        total_open_ports = []

        nm = nmap.PortScanner()
        port_scan = nm.scan(device_name_port_scan, arguments='-p- --open -sS --min-rate 5000 -n -Pn')['scan']
        if device_name_port_scan in port_scan.keys():
            total_open_ports = [*port_scan[device_name_port_scan]['tcp'].keys()]

        if len(total_open_ports) > 0:

            full_response = ''
            whatweb = ''

            if (80 in total_open_ports or 443 in total_open_ports) and device_format == 'URL':
                response = requests.get(device, verify=False).text.lower()
                whatweb = subprocess.run(['whatweb', device], stdout=subprocess.PIPE).stdout.decode('utf-8')
                whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
                full_response = response + whatweb
            
            elif 80 in total_open_ports and device_format == 'IP':
                http_device = 'http://' + device
                response = requests.get(http_device, verify=False).text.lower()
                whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
                whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
                full_response = response + whatweb

            elif 443 in total_open_ports and device_format == 'IP':
                http_device = 'https://' + device
                response = requests.get(http_device, verify=False).text.lower()
                whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE).stdout.decode('utf-8')
                whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()
                full_response = response + whatweb

            if full_response!='':
                print(full_response)
                probabilities = detectDevice(total_open_ports, full_response)
                print(probabilities)
                # max_probability = max(probabilities, key=probabilities.get)
                max_probability = max(probabilities)
                factor=1.0/sum(probabilities.values())
                normalised_d = probabilities
                for k in normalised_d:
                    normalised_d[k] = normalised_d[k] * factor
                # normalised_d = {k: v*factor for k, v in probabilities}
                print(normalised_d)
                detection['Open ports'] = ', '.join([str(p) for p in total_open_ports])
                detection['Device type'] = max_probability
                detection['Response'] = response
                detection['Whatweb'] = whatweb
        
        else: 
            detection['No open ports'] = 1

        res.append(detection)
    
    return res