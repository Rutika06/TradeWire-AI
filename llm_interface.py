import subprocess

def query_phi(prompt):
    result = subprocess.run(["ollama", "run", "phi", prompt], capture_output=True, text=True)
    return result.stdout.strip()
