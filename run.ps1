if (-not (Test-Path ".venv\Scripts\python.exe")) { py -m venv .venv }
. .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
