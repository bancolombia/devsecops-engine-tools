# Importamos el módulo git
import git


def repo_cloner(git_data: dict) -> str:
    git_token = git_data["git_token"]
    git_username = git_data["git_username"]
    repo_name = git_data["repo_templates"]
    # Definimos la URL del repositorio que queremos clonar
    # Agregamos el token de acceso personal después de https://
    repo_url = f"https://{git_token}@github.com/{git_username}/{repo_name}.git"

    # Definimos la carpeta donde queremos guardar el repositorio clonado
    repo_dir = repo_name

    # Clonamos el repositorio usando el método clone_from
    repo = git.Repo.clone_from(repo_url, repo_dir)
    # Mostramos la ubicación del repositorio clonado
    print(f"##vso[task.setvariable variable=TEMPLATES]{repo.working_tree_dir}")
    print(f"El repositorio se ha clonado en {repo.working_tree_dir}")

    return repo.working_tree_dir


if __name__ == "__main__":
    git_data = {
        "git_token": "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",
        "git_username": "bancolombia",
        "repo_templates": "NU0429001_devsecops_engine",
    }
    repo_cloner(git_data)
