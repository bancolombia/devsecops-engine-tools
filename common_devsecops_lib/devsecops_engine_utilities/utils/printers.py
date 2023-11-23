import pyfiglet


class Printers:
    @staticmethod
    def print_logo_tool():
        print(pyfiglet.figlet_format("DevSecOps Bancolombia", font="slant"))

    @staticmethod
    def print_title(title: str):
        print("\n")
        print("*" * len(title))
        print(title)
        print("*" * len(title))
        print("\n")
