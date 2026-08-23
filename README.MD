# VulnWise

VulnWise is a Streamlit application for personalised vulnerability triage. It matches vulnerability data against a security profile, ranks the most relevant findings, explains the results, and generates a PDF report.

## Features

- Upload or use a vulnerability dataset.
- Match findings to a security profile.
- Rank vulnerabilities by relevance and risk.
- Validate vulnerability, profile, and gold-set data.
- View vulnerability references and explanations.
- Download a PDF triage report.

## Requirements

- Python 3.10 or newer
- Windows PowerShell, macOS, or Linux

## Run on Windows

From the project directory, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
. .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Or use the included launcher:

```powershell
.\run.ps1
```

Open the URL shown by Streamlit, usually `http://localhost:8501`.

## Run on macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Or:

```bash
./run.sh
```

## Project Structure

```text
app.py                 Streamlit user interface
data/                  Profiles and vulnerability datasets
src/                   Matching, scoring, validation, and reporting logic
tests/                 Automated tests
tools/                 Developer validation utilities
Dockerfile             Container configuration
requirements.txt       Python dependencies
```

## Data Files

- `data/vulnerabilities.csv`: vulnerability records used by the application.
- `data/profile.json`: security profile used for personalised matching.
- `data/gold_set.csv`: expected matching results used for validation.

The application also includes equivalent sample data under `src/` and `data/datasets/` for development and testing.

## Run Tests

```bash
python -m pytest
```

Run the data validation utility with:

```bash
python tools/validate.py
```

## Docker

Build and run the application:

```bash
docker build -t vulnwise .
docker run --rm -p 8501:8501 vulnwise
```

Then open `http://localhost:8501`.

## Dependencies

- Streamlit
- pandas
- ReportLab
- pytest

## License

This project does not currently specify a license.
