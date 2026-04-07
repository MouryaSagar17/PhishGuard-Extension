"""
PhishGuard V2 - Quick Start Script

This script automates the setup and initialization of PhishGuard V2.
It guides through:
  1. Environment setup
  2. Dependency installation
  3. Model training
  4. Backend startup
  5. Verification
"""

import subprocess
import sys
import json
from pathlib import Path
from typing import Optional

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_header(text: str):
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}{text.center(60)}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")


def print_success(text: str):
    print(f"{GREEN}✓ {text}{RESET}")


def print_error(text: str):
    print(f"{RED}✗ {text}{RESET}")


def print_warning(text: str):
    print(f"{YELLOW}⚠ {text}{RESET}")


def print_info(text: str):
    print(f"{BLUE}ℹ {text}{RESET}")


def run_command(cmd: list, description: str, check: bool = True) -> bool:
    """Run a shell command and report status."""
    print_info(description)
    try:
        result = subprocess.run(cmd, check=check, capture_output=True, text=True)
        if result.returncode == 0:
            print_success(description)
            return True
        else:
            print_error(f"{description}\n{result.stderr}")
            return False
    except Exception as e:
        print_error(f"{description}: {e}")
        return False


def check_python_version():
    """Verify Python 3.9+"""
    print_header("Python Version Check")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 9:
        print_success(f"Python {version.major}.{version.minor}.{version.micro} detected")
        return True
    else:
        print_error(f"Python 3.9+ required (found {version.major}.{version.minor})")
        return False


def setup_virtual_env(project_root: Path):
    """Create virtual environment if not exists."""
    print_header("Virtual Environment Setup")
    
    venv_path = project_root / ".venv_v2"
    
    if venv_path.exists():
        print_warning(f"Virtual environment already exists at {venv_path}")
        return venv_path
    
    if run_command([sys.executable, "-m", "venv", str(venv_path)],
                   "Creating virtual environment"):
        print_success(f"Virtual environment created at {venv_path}")
        return venv_path
    else:
        print_error("Failed to create virtual environment")
        return None


def install_dependencies(project_root: Path, venv_path: Path):
    """Install Python dependencies."""
    print_header("Dependency Installation")
    
    requirements_path = "requirements.txt"
    
    if not requirements_path.exists():
        print_error(f"requirements.txt not found at {requirements_path}")
        return False
    
    # Determine pip command
    if sys.platform == "win32":
        pip_cmd = str(venv_path / "Scripts" / "pip")
    else:
        pip_cmd = str(venv_path / "bin" / "pip")
    
    return run_command(
        [pip_cmd, "install", "-r", str(requirements_path)],
        "Installing dependencies from requirements.txt"
    )


def train_model(project_root: Path):
    """Train V2 model."""
    print_header("Model Training")
    
    dataset_path = project_root / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    
    if not dataset_path.exists():
        print_error(f"Dataset not found at {dataset_path}")
        print_info("Please download dataset or check path")
        return False
    
    model_output = "models/phishing_model_v2.pkl"
    eval_output = "evaluation/eval_report.json"
    
    train_script = "ml/train_v2.py"
    
    if not train_script.exists():
        print_error(f"Training script not found at {train_script}")
        return False
    
    # Determine Python command
    if sys.platform == "win32":
        python_cmd = str((project_root / ".venv_v2" / "Scripts" / "python").resolve())
    else:
        python_cmd = str((project_root / ".venv_v2" / "bin" / "python").resolve())
    
    return run_command(
        [python_cmd, str(train_script),
         "--data", str(dataset_path),
         "--out", str(model_output),
         "--eval-out", str(eval_output),
         "--max-rows", "10000"],  # Adjust for quick demo
        "Training V2 model with multiple architectures"
    )


def verify_model(project_root: Path):
    """Verify model was created."""
    print_header("Model Verification")
    
    model_path = project_root / "v2" / "models" / "phishing_model_v2.pkl"
    eval_path = project_root / "v2" / "evaluation" / "eval_report.json"
    
    if model_path.exists():
        size_mb = model_path.stat().st_size / (1024 * 1024)
        print_success(f"Model file exists ({size_mb:.1f} MB)")
    else:
        print_error("Model file not found")
        return False
    
    if eval_path.exists():
        try:
            with open(eval_path, "r") as f:
                results = json.load(f)
            champion = results.get("champion", "unknown")
            models = results.get("models_evaluated", [])
            print_success(f"Evaluation report found")
            print_info(f"  - Champion model: {champion}")
            print_info(f"  - Models evaluated: {len(models)}")
            return True
        except Exception as e:
            print_error(f"Failed to read evaluation report: {e}")
            return False
    
    return True


def test_backend(project_root: Path):
    """Test backend with health check."""
    print_header("Backend Health Check")
    
    import subprocess
    import time
    
    # Determine Python command
    if sys.platform == "win32":
        python_cmd = str((project_root / ".venv_v2" / "Scripts" / "python").resolve())
    else:
        python_cmd = str((project_root / ".venv_v2" / "bin" / "python").resolve())
    
    backend_script = "backend/app_v2.py"
    
    if not backend_script.exists():
        print_error(f"Backend script not found at {backend_script}")
        return False
    
    print_warning("This will start the backend server. Press Ctrl+C to stop.")
    print_info("Testing health endpoint after 3 seconds...")
    
    try:
        # Start backend
        proc = subprocess.Popen(
            [python_cmd, str(backend_script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(3)
        
        # Test health
        import urllib.request
        try:
            response = urllib.request.urlopen("http://127.0.0.1:8765/health")
            if response.status == 200:
                print_success("Backend health check passed")
                return True
        except Exception as e:
            print_error(f"Health check failed: {e}")
        
        # Cleanup
        proc.terminate()
        return False
    
    except Exception as e:
        print_error(f"Backend test failed: {e}")
        return False


def main():
    """Run setup wizard."""
    print_header("PhishGuard V2 - Quick Start Setup")
    
    project_root = Path(__file__).parent.parent
    
    # Step 1: Python version
    if not check_python_version():
        print_error("Setup failed: Python version requirement not met")
        sys.exit(1)
    
    # Step 2: Virtual environment
    venv_path = setup_virtual_env(project_root)
    if not venv_path:
        print_error("Setup failed: Virtual environment creation failed")
        sys.exit(1)
    
    # Step 3: Dependencies
    if not install_dependencies(project_root, venv_path):
        print_error("Setup failed: Dependency installation failed")
        sys.exit(1)
    
    # Step 4: Model training (optional)
    print_header("Model Training (Optional)")
    print_info("Training requires dataset and may take several minutes")
    train = True
    
    if train:
        if not train_model(project_root):
            print_warning("Model training skipped or failed")
    else:
        print_info("Skipping model training")
    
    # Step 5: Verify
    if not verify_model(project_root):
        print_warning("Model verification failed - make sure to train the model")
    
    # Step 6: Test backend (optional)
    print_header("Backend Testing (Optional)")
    test = True
    
    if test:
        test_backend(project_root)
    
    # Summary
    print_header("Setup Complete ✅")
    
    print("""
Next steps:

1. Start the backend:
   Windows:
     .venv_v2\\Scripts\\python v2\\backend\\app_v2.py
   
   Unix/macOS:
     .venv_v2/bin/python v2/backend/app_v2.py

2. Configure the extension:
   - Open extension settings
   - Set API Base URL: http://127.0.0.1:8765
   - Enable auto-scan (optional)

3. Test the extension:
   - Click "Scan Now" button
   - Try demo mode

4. Read documentation:
   - v2/README_V2.md - Complete documentation
   - v2/UPGRADE_GUIDE.md - Migration guide

For help:
   python v2/backend/app_v2.py --help
   python v2/ml/train_v2.py --help
""")
    
    print_success("PhishGuard V2 is ready to use!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nSetup cancelled by user")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
