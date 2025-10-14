import nmap
import json
from flask import Flask, render_template, request, jsonify
import re # Necesario para la validación de puertos

# --- CONFIGURACIÓN DE FLASK ---
app = Flask(__name__)

# --- FUNCIONES DE ESCANEO NMAP ---
def run_nmap_scan(target_ip, port_range):
    """
    Ejecuta un escaneo Nmap para detección de servicios y versiones (-sV).
    """
    nm = nmap.PortScanner()
    
    # Argumentos del escaneo: -sV (Detección de versión), -T4 (Velocidad), -p (Puertos)
    arguments = f'-sV -T4 -p {port_range}'
    
    try:
        # Ejecutar el escaneo
        nm.scan(hosts=target_ip, arguments=arguments)
        
        open_ports = []
        
        # Procesar resultados
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    port_info = nm[host]['tcp'][port]
                    
                    if port_info['state'] == 'open':
                        # Construir la información detallada del servicio/versión
                        service_info = f"{port_info['product']} {port_info['version']}".strip()
                        if not service_info:
                            service_info = port_info['name'] if port_info['name'] else 'Versión no detectada'

                        open_ports.append({
                            "port": port,
                            "status": "ABIERTO",
                            "name": port_info['name'] if port_info['name'] else 'Desconocido',
                            "full_service": service_info
                        })
                        
        return open_ports
        
    except nmap.PortScannerError as e:
        if "nmap program was not found" in str(e):
             raise Exception("Nmap no está instalado en el sistema. Ejecuta: sudo apt install nmap")
        raise e
    except Exception as e:
        raise Exception(f"Error en Nmap: {str(e)}")
    
def run_os_scan(target_ip):
    """
    Ejecuta un escaneo Nmap para deteccion de Sistema Operativo (-0).
    """
    nm = nmap.PortScanner()

    # Argumentos del escaneo: -0 (Deteccion de OS)
    arguments = '-O'

    try:
        nm.scan(hosts=target_ip, arguments=arguments)

        # Verificar si hay informacion de OS para el host
        if target_ip in nm.all_hosts() and 'osmatch' in nm[target_ip]:
            os_matches = nm[target_ip]['osmatch']
            if os_matches:
                # Retorna el primer match con mayor precision 
                match = os_matches[0]
                return {
                    "name: match['name'],"
                    "accuracy": match['accuracy']
                }
            
        return None # No se pudo detectar la OS
    
    except Exception as e:
        raise Exception(f"Error en la deteccion de OS con Nmap: {str(e)}")

def run_vulnerability_scan(target_ip, port_range='1-1024'):
    """
    Ejecuta Nmap con el script de vulnerabilidades NSE (-sV --script vuln). Requiere root.
    """
    nm = nmap.PortScanner()
    # -sV: deteccion de version, --script vuln: ejecutar scripts de vulnerabilidad
    arguments = f'-sV --script vuln -T4 -p {port_range}'

    try:
        nm.scan(hosts=target_ip, arguments=arguments)

        vulnerabilities = []

        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    port_info = nm[host]['tcp'][port]

                    # El script 'vuln' anade la informacion bajo 'script'
                    if 'script' in port_info and 'vuln' in port_info['script']:
                        vuln_output = port_info['script']['vuln'].strip()

                        vulnerabilities.append({
                            "port": port,
                            "service": port_info.get('name', 'Desconocido'),
                            "output": vuln_output
                        })

        return vulnerabilities
    
    except Exception as e:
        raise Exception(f"Error en el escaneo de vulnerabilidades Nmap: {str(e)}")

# --- RUTAS DE FLASK ---

@app.route('/')
def index():
    """Ruta principal."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Ruta API para el escaneo."""
    data = request.json
    target_ip = data.get('ip')
    port_range_str = data.get('ports', '1-1024')
    
    if not target_ip:
        return jsonify({"error": "IP objetivo requerida"}), 400

    # Validación de formato de puertos (para evitar inyecciones)
    if not re.match(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$', port_range_str):
        return jsonify({"error": "Formato de puertos inválido. Use '80', '1-1024' o '22,80,443'."}), 400
            
    try:
        results = run_nmap_scan(target_ip, port_range_str)
        return jsonify({"ip": target_ip, "ports": results})
    except Exception as e:
        return jsonify({"error": f"Error en el escaneo: {str(e)}"}), 500
    
  # ... (código anterior) ...

@app.route('/os_detect', methods=['POST'])
def os_detect():
    """Ruta API para la detección de Sistema Operativo."""
    data = request.json
    target_ip = data.get('ip')

    if not target_ip:
        return jsonify({"error": "IP objetivo requerida"}), 400

    try:
        result = run_os_scan(target_ip)
        return jsonify({"ip": target_ip, "os": result})
    except Exception as e:
        return jsonify({"error": f"Error en la detección de OS: {str(e)}"}), 500
    
@app.route('/vuln_scan', methods=['POST'])
def vuln_scan():
    """Ruta API para el escaneo de vulnerabilidades."""
    data = request.json
    target_ip = data.get('ip')
    port_range_str = data.get('ports', '1-1024')

    if not target_ip:
        return jsonify({"error": "IP objetivo requerida"}), 400
    
    if not re.match(r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$', port_range_str):
        return jsonify({"error": "Formato de puertos invalido."}), 400
    
    try:
        results = run_vulnerability_scan(target_ip, port_range_str)
        return jsonify({"ip": target_ip, "vulnerabilities": results})
    except Exception as e:
        return jsonify({"error": f"Error en el escaneo de vulnerabilidades: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, threaded=True)# ... (código anterior) ...
