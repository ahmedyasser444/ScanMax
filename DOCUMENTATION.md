# 📘 ScanMax Pro Documentation

> ⚡ Smart Guide to Using ScanMax Pro Efficiently

---

## 🧠 What is ScanMax Pro?

**ScanMax Pro** is a modular reconnaissance and vulnerability scanning tool designed to automate and simplify security testing workflows.

It combines multiple tools into one unified pipeline and optionally enhances results using AI.

---

## ⚙️ How It Works

ScanMax follows this pipeline:

```text
Target → Recon → Subdomains → Live Hosts → Fuzzing → Results → AI Analysis (optional)
```

### 🔹 Step-by-step:

1. **Port Scanning**
   - Uses `nmap` to detect open ports and services

2. **Subdomain Enumeration**
   - Uses `subfinder`

3. **Live Host Detection**
   - Uses `httpx`

4. **Fuzzing (Optional)**
   - Uses `gobuster` or `ffuf`

5. **AI Analysis (Optional)**
   - Summarizes findings into readable report

---

## 🚀 Getting Started

### Basic Usage

```bash
scanmax example.com
```

---

### Run Specific Tools

```bash
scanmax example.com --tools nmap subfinder httpx
```

---

### Enable Fuzzing

```bash
scanmax example.com --use-gobuster --wordlist /path/to/wordlist.txt
```

---

### Use FFUF Instead

```bash
scanmax example.com --use-ffuf --wordlist /path/to/wordlist.txt
```

---

### Enable AI Analysis

```bash
scanmax example.com --hf-model google/flan-t5-small
```

---

## ⚙️ Important Options

| Option            | Description |
|------------------|------------|
| `--tools`        | Select tools to run |
| `--use-gobuster` | Enable Gobuster |
| `--use-ffuf`     | Enable FFUF |
| `--wordlist`     | Path to wordlist |
| `--threads`      | Number of threads |
| `-o`             | Output directory |
| `--dry-run`      | Show commands without execution |

---

## 📂 Output Explained

### 📁 results/

Contains raw outputs:

- `nmap_*.txt` → Open ports
- `subdomains_*.txt` → Found subdomains
- `httpx_*.txt` → Live hosts
- `ffuf_*.json/csv` → Fuzzing results

---

### 📁 reports/

Contains AI-generated reports:

- `*_ai_report.md`

---

## 📊 Example Output

```text
[+] Found 12 subdomains
[+] 8 live hosts detected
[+] 3 interesting endpoints found
```

---

## 🤖 AI Feature Explained

> ⚠️ Experimental

AI reads raw scan results and generates:

- Summary
- Key findings
- Possible vulnerabilities

Supported backends:
- HuggingFace
- OpenAI
- Ollama

---

## ⚠️ Best Practices

- ✅ Use clean wordlists
- ✅ Limit threads on weak machines
- ✅ Always verify AI results manually
- ❌ Do NOT scan without permission

---

## 🧪 Troubleshooting

### ❌ Tool not found

```bash
command not found: subfinder
```

✔️ Fix:
```bash
export PATH=$PATH:$HOME/go/bin
```

---

### ❌ Slow performance

✔️ Reduce threads:
```bash
--threads 5
```

---

## 🔥 Tips

- Combine tools for better results:
```bash
scanmax target.com --tools nmap subfinder httpx --use-ffuf
```

- Use large wordlists for deep fuzzing

---

## 📌 Roadmap

- [ ] Improve AI accuracy
- [ ] Add GUI interface
- [ ] Add auto-report dashboard
- [ ] Add vulnerability scoring

---

## 👨‍💻 Author

Ahmed444  
Cybersecurity Enthusiast & Developer

---

## ⭐ Final Note

> "Scan smart. Not just fast."