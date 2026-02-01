# Process Guardian

**Process Guardian** is a Python tool for monitoring Linux processes, tracking high CPU and memory usage, and collecting system and process snapshots for troubleshooting and analysis.

## Current Features
- Scan running processes for **CPU and memory thresholds**
- Track **sustained offenders** accross multiple scans
- Collect **process snapshots** (metadata, CPU/memory usage, threads, open files)
- Capture **journald** logs for offending processes
- Take **system snapshots** (`ps`, `top`, `df`, `free`) for context
- Configurable thresholds, scan interval, and sustained breach count via `config/config.yaml`

## Future Enhancements
- **Tracer** -  monitor system calls vian `strace`
- **Terminator** - gracefully, force kill, and restart processes
- **Reporter** - generate alers, summaries, or visualization
- **Extended automation & CI/CD integration** - testing. monitoring, and deployement pipelines

These additions will extend the tool for **deeper systems analysis, automated responses, and reporting workflows.**

## Installation

```bash
git clone https://github.com/camrohwer/process-guardian.git
cd process-guardian

python -m venv venv
source venv/bin/activate

pip install -r requirements-dev.txt
pre-commit install
```

## Configuration
Edit `config/config.yaml` to adjust thresholds and scan settings:

```yaml
thresholds:
  cpu_percent: 80
  memory_percent: 70

scan:
  interval_seconds: 5
  sustained_breach_count: 2
```

## Usage
Run the main script:
```bash
python src/main.py
```
Behaviour:
- Monitors processes at the configured interval
- Tracks offenders exceeding thresholds
Collects evidence (proc snapshot, journal logs, system snapshot)
- Stops gracefully on `Ctrl+C`

## Project Structure

```code
process-guardian/
├─ config/
│  └─ config.yaml
├─ src/
│  ├─ __init__.py
│  ├─ main.py
│  ├─ scanner.py
│  ├─ collector.py
│  └─ models.py
├─ tests/
├─ .gitignore
├─ .pre=commit-config.yaml
├─ README.md
├─ LICENSE
└─ requirements-dev.txt
```

## License
MIT License © 2026 Cam Rohwer