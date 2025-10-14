🛡️ NetSpectre: Herramienta Full-Stack de Análisis de Seguridad (Nmap)

Python∣Flask∣Nmap∣TailwindCSS
📝 Descripción del Proyecto
NetSpectre es una herramienta web de Ciberseguridad/Hacking Ético diseñada para realizar análisis de red profundos utilizando el poder del motor Nmap. Esta aplicación Full-Stack (Frontend y Backend) permite a los usuarios escanear un host objetivo para descubrir servicios, determinar el sistema operativo y buscar vulnerabilidades comunes.

Es un proyecto clave de portafolio que demuestra experiencia en el desarrollo de herramientas de seguridad operativas.

Características Clave
Escaneo de Puertos y Servicios (-sV): Identifica qué puertos están abiertos y qué servicios (como Apache, SSH, etc.) y versiones están corriendo en ellos.

Detección de Sistema Operativo (-O): Intenta determinar el sistema operativo del host objetivo (requiere permisos de root).

Escaneo de Vulnerabilidades (NSE): Utiliza el Nmap Scripting Engine (--script vuln) para buscar vulnerabilidades básicas y conocidas en los servicios detectados.

Tecnología Full-Stack: Python/Flask como backend y motor Nmap, y una interfaz de usuario moderna con HTML/Tailwind CSS.

🛠️ Tecnologías Utilizadas
Backend: Python 3, Flask, python-nmap.

Frontend: HTML5, JavaScript (Fetch API), Tailwind CSS.

Core: Nmap (Motor de escaneo de red).

🚀 Instalación y Ejecución
Sigue estos pasos para levantar el servidor en tu entorno Linux (como Crostini/WSL):

1. Clonar el Repositorio
git clone [TU_ENLACE_AQUÍ]
cd NetSpectre


2. Instalar Nmap (Prerrequisito)
Asegúrate de tener Nmap instalado en tu sistema.

sudo apt update
sudo apt install nmap


3. Configurar el Entorno Virtual de Python
Crea y activa un entorno virtual para aislar las dependencias:

python3 -m venv venv
source venv/bin/activate


4. Instalar Dependencias de Python
Instala las librerías necesarias (Flask y la interfaz de Nmap para Python):

pip install flask python-nmap


5. Ejecutar el Servidor (Requiere sudo)
Dado que la Detección de OS y el Escaneo de Vulnerabilidades necesitan privilegios de administrador para funcionar, debes ejecutar el script usando sudo y especificando el intérprete de Python dentro del entorno virtual:

sudo venv/bin/python3 app.py


6. Acceder a la Aplicación
Abre tu navegador y navega a:

[http://127.0.0.1:5000/](http://127.0.0.1:5000/)


💡 Uso de la Herramienta
IP Objetivo: Ingresa la IP que deseas escanear (ej. 127.0.0.1 para tu propia máquina o la IP de tu router).

Rango de Puertos: Especifica el rango (ej. 1-1024 o 80,443).

Selecciona el Escaneo: Haz clic en ESCANEO DE PUERTOS, DETECCIÓN OS o ESCANEO VULN.

Desarrollado por Carlos Sandoval Rodriguez - Portafolio-

