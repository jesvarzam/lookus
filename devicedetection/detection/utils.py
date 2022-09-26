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
    full_response = ''
    http_device = device

    if not validators.url(device):
        http_device = 'http://' + device

    whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')
    whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb)
    http_device = follow_redirect(whatweb, http_device)
    try:
        response = requests.get(http_device, verify=False, timeout=10).text.lower()
    except:
        response = ''
    whatweb = subprocess.run(['whatweb', http_device], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')
    whatweb = re.sub('\x1B\[([0-9]{1,3}((;[0-9]{1,3})*)?)?[m|K]', '', whatweb).lower()

    full_response = response + whatweb
    return ['\n'.join(set(full_response.split('\n'))), response, whatweb]


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
                response = return_response(device)[0]
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


def follow_redirect(whatweb, url):
    split_headers = whatweb.split('\n')
    for split_h in split_headers:
        headers = split_h.split(',')
        if '302' in split_h:
            for h in headers:
                if 'RedirectLocation' in h:
                    adding_url = re.search(r"((?<=\[)(.*?)(?=\]))", h)[0]
                    url = url + adding_url
                    break
        elif '301' in split_h:
            for h in headers:
                if 'RedirectLocation' in h:
                    url = re.search(r"((?<=\[)(.*?)(?=\]))", h)[0]
                    break
    return url


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
            possible_devices['Impresora'] += 3
    
    for keyword in ROUTER_KEYWORDS:
        if keyword in response:
            possible_devices['Router'] += 3
    
    for keyword in CAMERA_KEYWORDS:
        if keyword in response:
            possible_devices['Cámara'] += 3

    return possible_devices


def analyze_response(possible_devices, response, user, use_own_dicc):

    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/web_dicc.txt')
    else: f = open('detection/diccs/web_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Página web personal'] += 1
    
    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/router_dicc.txt')
    else: f = open('detection/diccs/router_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Router'] += 1
    
    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/printer_dicc.txt')
    else: f = open('detection/diccs/printer_dicc.txt')
    for line in f:
        if line.strip() in response:
            possible_devices['Impresora'] += 1

    if use_own_dicc: f = open('detection/diccs/' + str(user.username) + str(user.id) + '/camera_dicc.txt')
    else: f = open('detection/diccs/camera_dicc.txt')
    for line in f:
        if line.strip() in response:
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

    template="<!DOCTYPE html>\n" + "<html>\n" + "<head>\n" + "<meta charset='UTF-8'>\n" + "<style>\n"
    template+="table, th, td {border: 1px solid black;border-collapse: collapse;border-spacing: 15px;padding: 10px; margin-top: 20px}\n"
    template+="</style>\n" + "</head>\n"
    template+="<body>\n"
    template+="<h1>Detección del dispositivo " + str(data[0]) + "\n</h1>\n"
    template+="<strong>" + "Fecha de detección: " + detection.detection_date.strftime("%d-%b-%Y-%H-%M-%S") + "</strong>\n"
    template+="<table style='width:50%'>\n"
    template+='<tr>\n'
    template+="<th style='background-color:#f66151;width:85;color:white'>\n" + headers[0] + "\n</th>\n"
    template+="</tr>\n"
    template+="<tr style='text-align:center'>\n"
    template+="<td>\n" + str(data[0]) + " (" + str(data[2]) + ") " + "\n</td>\n"
    template+="</tr>\n"
    template+="</table>\n"
    template+="<table style='width:50%'>\n"
    template+='<tr>\n'
    template+="<th style='background-color:#f66151;width:85;color:white'>\n" + headers[1] + "\n</th>\n"
    template+="</tr>\n"
    template+="<tr style='text-align:center'>\n"
    template+="<td>\n" + str(data[1]) + "\n</td>\n"
    template+="</tr>\n"
    template+="</table>\n"
    template+="<table style='width:50%'>\n"
    template+='<tr>\n'
    template+="<th style='background-color:#f66151;width:85;color:white'>\n" + headers[3] + "\n</th>\n"
    template+="</tr>\n"

    if data[3] == 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información':
        template+="<tr style='text-align:center'>\n"
        template+="<td>\n" + str(data[3]) + "\n</td>\n"
        template+="</tr>\n"
    
    else:
        for http_info in data[3]:
            template+="<tr style='text-align:center'>\n"
            template+="<td>\n" + str(http_info) + "\n</td>\n"
            template+="</tr>\n"

    template+="</table>\n"
    template_pdf="<form style='margin-top: 20px' action='/detection/pdf/{}'>\n".format(str(detection.id)) 
    template_pdf+="<input type='submit' value='Exportar a PDF' />\n" + "</form>\n"
    template+="</body>\n" + "</html>\n"

    name1=str(detection.id) + ".html"
    file1 = open('detection/templates/reports/' + name1, "w")
    file1.write(template + template_pdf + "</body>" + "</html>")
    file1.close()

    name2=str(detection.id) + "pdf.html"
    file2 = open('detection/templates/reports/' + name2, "w")
    file2.write(template + "</body>" + "</html>")
    file2.close()


def create_table_html_for_range(devices, device_detected, detection):
    headers = ['Dispositivo', 'Puertos abiertos', 'Dispositivo detectado', 'Cabeceras HTTP']

    template="<!DOCTYPE html>\n" + "<html>\n" + "<head>\n" + "<meta charset='UTF-8'>\n" + "<style>\n"
    template+="table, th, td {border: 1px solid black;border-collapse: collapse;border-spacing: 15px;padding: 10px; margin-top: 20px}\n"
    template+="</style>\n" + "</head>\n"
    template+="<body>\n"
    template+="<h1>Detección del rango de red " + device_detected + "</h1>\n"
    template+="<strong style='display:inline'>" + "Fecha de detección: <strong>\n" 
    template+="<p style='display:inline'>" + detection.detection_date.strftime("%d-%b-%Y-%H-%M-%S") + "</p>\n"
    template+="<hr>\n"
    counter = 1
    for d in devices:
        http_info = 'El dispositivo no tiene un servidor HTTP, por lo que no se ha podido obtener información'
        template+="<table id='myTable' class='mytable' data-name='mytable' style='width:50%'>\n"
        template+="<p>Dispositivo " + str(counter) + "<p>\n"
        template+="<tr>\n"
        template+="<th style='background-color:#f66151;width:85;color:white'>" + headers[0] + "</th>\n"
        template+="</tr>\n"
        template+="<tr style='text-align:center'>\n"
        template+="<td>" + str(d['Device']) + " (" + str(d['Device type']) + ") " + "</td>\n"
        template+="</tr>\n"
        template+="<tr>\n"
        template+="<th style='background-color:#f66151;width:85;color:white'>" + headers[1] + "</th>\n"
        template+="</tr>\n"
        template+="<tr style='text-align:center'>\n"
        if 'Open ports' in d: template+="<td>" + str(d['Open ports']) + "</td>\n"
        if 'No open ports' in d: template+="<td>" + str(d['No open ports']) + "</td>\n"
        template+="</tr>\n"
        template+="<tr>\n"
        template+="<th style='background-color:#f66151;width:85;color:white'>" + headers[3] + "</th>\n"
        template+="</tr>\n"
        if 'Whatweb' in d: 
            whatweb = d['Whatweb']
            whatweb = whatweb.replace('%', '').split('\n')
            whatweb = list(set(', '.join(whatweb).split(', ')[:-1]))
            http_info = whatweb
            for h in http_info:
                template+="<tr style='text-align:center'>\n"
                template+="<td>" + str(h) + "</td>\n"
                template+="</tr>\n"
        if 'Whatweb' not in d:
            template+="<tr style='text-align:center'>\n"
            template+="<td>" + http_info + "</td>\n"
            template+="</tr>\n"
        
        template+="</table>\n"
        template+="<br>\n"
        template+="<hr>\n"
        counter+=1
        
    template_pdf="<form style='margin-top: 20px' action='/detection/pdf/{}'>".format(str(detection.id)) + "<input type='submit' value='Exportar a PDF' />" + "</form>\n"
    template+="</body>\n" + "</html>\n"

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

    if validators.url(device_name):
        device_name_port_scan = getIP(device_name)

    total_open_ports = []

    nm = nmap.PortScanner()
    port_scan = nm.scan(device_name_port_scan, arguments='-p- --open -sS --min-rate 5000 -n -Pn')['scan']
    if device_name_port_scan in port_scan.keys():
        total_open_ports = [*port_scan[device_name_port_scan]['tcp'].keys()]

    if len(total_open_ports) > 0:
        full_response_list = return_response(device_name)
        full_response = full_response_list[0]
        response = full_response_list[1]
        whatweb = full_response_list[2]

        if full_response!='':
            probabilities = detectDevice(total_open_ports, full_response, user, use_own_dicc)
            if sum(probabilities.values()) == 0:
                factor = 0.0
            else:
                factor = 1.0/sum(probabilities.values())
            for p in probabilities:
                probabilities[p] = round(probabilities[p]*factor*100.00, 2)
            res['Open ports'] = ', '.join([str(p) for p in total_open_ports])
            res['Device type'] = ', '.join(p + ': ' + str(probabilities[p]) + '%' for p in probabilities)
            res['Response'] = response
            res['Whatweb'] = whatweb

        else:
            probabilities = detectPorts(total_open_ports)
            if sum(probabilities.values()) == 0:
                factor = 0.0
            else:
                factor = 1.0/sum(probabilities.values())
            for p in probabilities:
                probabilities[p] = round(probabilities[p]*factor*100.00, 2)
            res['Open ports'] = ', '.join([str(p) for p in total_open_ports])
            res['Device type'] = ', '.join(p + ': ' + str(probabilities[p]) + '%' for p in probabilities)
    
    else:
        res['No open ports'] = 'No se han detectado puertos abiertos'
        res['Device type'] = 'Desconocido'

    return res


def range_device_detection(range_device, user, use_own_dicc):

    res = []

    for device in ipaddress.IPv4Network(range_device.name):

        device = str(device)

        detection = {}
        detection['Device'] = device

        device_name_port_scan = device

        if validators.url(device):
            device_name_port_scan = getIP(device)

        total_open_ports = []

        nm = nmap.PortScanner()
        port_scan = nm.scan(device_name_port_scan, arguments='-p- --open -sS --min-rate 5000 -n -Pn')['scan']
        if device_name_port_scan in port_scan.keys():
            total_open_ports = [*port_scan[device_name_port_scan]['tcp'].keys()]

        if len(total_open_ports) > 0:
            full_response_list = return_response(device)
            full_response = full_response_list[0]
            response = full_response_list[1]
            whatweb = full_response_list[2]

            if full_response!='':
                probabilities = detectDevice(total_open_ports, full_response, user, use_own_dicc)
                if sum(probabilities.values()) == 0:
                    factor = 0.0
                else:
                    factor = 1.0/sum(probabilities.values())
                for p in probabilities:
                    probabilities[p] = round(probabilities[p]*factor*100.00, 2)
                detection['Open ports'] = ', '.join([str(p) for p in total_open_ports])
                detection['Device type'] = ', '.join(p + ': ' + str(probabilities[p]) + '%' for p in probabilities)
                detection['Response'] = response
                detection['Whatweb'] = whatweb
            
            else:
                probabilities = detectPorts(total_open_ports)
                if sum(probabilities.values()) == 0:
                    factor = 0.0
                else:
                    factor = 1.0/sum(probabilities.values())
                for p in probabilities:
                    probabilities[p] = round(probabilities[p]*factor*100.00, 2)
                res['Open ports'] = ', '.join([str(p) for p in total_open_ports])
                res['Device type'] = ', '.join(p + ': ' + str(probabilities[p]) + '%' for p in probabilities)
        
        else: 
            detection['No open ports'] = 'No se han detectado puertos abiertos'
            detection['Device type'] = 'Desconocido'

        res.append(detection)
    
    return res