import pyfiglet


class Printers:
    @staticmethod
    def print_logo_tool():
        print(pyfiglet.figlet_format("DevSecOps Bancolombia", font="slant"))
