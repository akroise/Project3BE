import os
import subprocess

def get_imports_from_file(file_path):
    imports = set()
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line.startswith("import ") or line.startswith("from "):
                module = line.split()[1].split('.')[0]
                if module not in ("__future__", "typing", "os", "sys", "json"):
                    imports.add(module)
    return imports

def main():
    all_imports = set()
    for root, _, files in os.walk("."):
        for file in files:
            if file.endswith(".py"):
                all_imports |= get_imports_from_file(os.path.join(root, file))

    print("Detected modules:", all_imports)
    with open("requirements.txt", "w") as req:
        for pkg in all_imports:
            try:
                version = subprocess.check_output(
                    ["pip", "show", pkg], universal_newlines=True
                )
                for line in version.splitlines():
                    if line.startswith("Version:"):
                        ver = line.split(":", 1)[1].strip()
                        req.write(f"{pkg}=={ver}\n")
                        break
            except subprocess.CalledProcessError:
                req.write(f"{pkg}\n")
    print("✅ requirements.txt created.")

if __name__ == "__main__":
    main()
