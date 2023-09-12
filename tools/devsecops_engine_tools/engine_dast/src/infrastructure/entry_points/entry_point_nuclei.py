import argparse
import sys
from devsecops_engine_utilities.utils.printers import (
    Printers,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei_module import nuclei
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei_deserializer import NucleiDesealizator

from devsecops_engine_tools.engine_dast.src.domain.usecases.nuclei_process import NucleiProcess

def get_inputs_from_cli(args):
    parser = argparse.ArgumentParser(description="Ejecuta Nuclei desde la línea de comandos")
    parser.add_argument("-t", "--template", required=True, help="Plantilla de Nuclei a utilizar")
    parser.add_argument("-l", "--url", required=True, help="url or targets")
    parser.add_argument("--tags", nargs="*", help="Etiquetas para filtrar las plantillas de Nuclei")
    args = parser.parse_args()

    return (
        args.url,
        args.template,
    )

def init_nuclei(url, template, tags=None):
    json_data = nuclei(url, template)
    return json_data

def start_process():
    print(get_inputs_from_cli(sys.argv[1:]))
    url, template = get_inputs_from_cli(sys.argv[1:])
    Printers.print_logo_tool()
    json_data = init_nuclei(url, template)
    nuclei_data = NucleiDesealizator(json_data)
    nuclei_process= NucleiProcess(nuclei_data.scan)
    nuclei_process.get_result_scans()
    vuln_list = nuclei_process.get_list_vulnerabilities()
    nuclei_process.print_table(vuln_list)
