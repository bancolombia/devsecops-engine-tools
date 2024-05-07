import os


class EnvVariables:
    @staticmethod
    def get_value(env_name):
        env_var = os.environ.get(env_name)
        if env_var is None:
            raise ValueError(f"La variable de entorno {env_name} no está definida")
        return env_var
