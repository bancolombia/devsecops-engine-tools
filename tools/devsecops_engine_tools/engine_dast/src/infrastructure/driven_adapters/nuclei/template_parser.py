# Importar la librería YAML
import yaml

# Definir el JSON con las operaciones
json_data = {
    "endpoint": "https://api.us.apiconnect.ibmcloud.com",
    "operations": [
        {
            "operation": {
                "security_auth": {"type": "client_secret"},
                "method": "GET",
                "path": "/bancolombiabluemix-dev/testing/tec/v2/sales-service/cross-channel/service-points/branches?",
                "parm": {"longitude": "6.247759", "latitude": "-75.565575"},
                "headers": {
                    "accept": "application/vnd.bancolombia.v1+json",
                    "Cache-Control": "no-cache",
                },
            }
        },
        {
            "operation": {
                "security_auth": {"type": "client_secret"},
                "method": "GET",
                "path": "/bancolombiabluemix-dev/testing/tec/v2/sales-service/cross-channel/service-points/atms?",
                "parm": {"longitude": "6.247759", "latitude": "-75.565575"},
                "headers": {
                    "accept": "application/vnd.bancolombia.v1+json",
                    "Cache-Control": "no-cache",
                },
            }
        },
        {
            "operation": {
                "security_auth": {"type": "client_secret"},
                "method": "GET",
                "path": "/bancolombiabluemix-dev/testing/tec/v2/sales-service/cross-channel/service-points/agents?",
                "parm": {"longitude": "6.247759", "latitude": "-75.565575"},
                "headers": {
                    "accept": "application/vnd.bancolombia.v1+json",
                    "Cache-Control": "no-cache",
                },
            }
        },
    ],
}

# Definir una lista con los nombres de los templates
template_names = [
    "bancolombia-service-points-branches",
    "bancolombia-service-points-atms",
    "bancolombia-service-points-agents",
]

# Definir una lista con las descripciones de los templates
template_descriptions = [
    "Detecta los puntos de servicio de Bancolombia para las sucursales.",
    "Detecta los puntos de servicio de Bancolombia para los cajeros automáticos.",
    "Detecta los puntos de servicio de Bancolombia para los agentes.",
]


# Definir una función para crear un template a partir de una operación
def create_template(operation, template_name, template_description):
    # Crear un diccionario vacío para el template
    template = {}
    # Asignar el ID, la información y la severidad del template
    template["id"] = template_name
    template["info"] = {
        "name": template_name,
        "author": "user",
        "severity": "info",
        "description": template_description,
    }
    # Crear una lista vacía para las peticiones HTTP
    template["http"] = []
    # Crear un diccionario para la petición HTTP
    http = {}
    # Asignar el método, el path, los parámetros y los headers de la operación
    http["method"] = operation["method"]
    http["path"] = [
        json_data["endpoint"]
        + operation["path"]
        + "longitude="
        + operation["parm"]["longitude"]
        + "&latitude="
        + operation["parm"]["latitude"]
    ]
    http["headers"] = operation["headers"]
    # Crear una lista vacía para los matchers
    http["matchers"] = []
    # Crear un diccionario para el matcher
    matcher = {}
    # Asignar el tipo y las palabras del matcher
    matcher["type"] = "word"
    matcher["words"] = ["servicePointId", "servicePointName"]
    matcher["part"] = "body"
    # Añadir el matcher a la lista de matchers
    http["matchers"].append(matcher)
    # Añadir la petición HTTP a la lista de peticiones HTTP
    template["http"].append(http)
    # Devolver el template como un diccionario
    return template


# Recorrer las operaciones del JSON
for i in range(len(json_data["operations"])):
    # Obtener la operación actual
    operation = json_data["operations"][i]["operation"]
    # Obtener el nombre y la descripción del template correspondiente
    template_name = template_names[i]
    template_description = template_descriptions[i]
    # Crear el template a partir de la operación
    template = create_template(operation, template_name, template_description)
    # Convertir el template a un formato YAML
    template_yaml = yaml.dump(template, sort_keys=False)
    # Guardar el template en un archivo con el mismo nombre
    with open(template_name + ".yaml", "w") as file:
        file.write(template_yaml)
    # Imprimir un mensaje de confirmación
    print(f"Se ha creado el template {template_name}.yaml")
