# Comprehensive Network and Reconnaissance Scanner (ariesgad)

This is a comprehensive, menu-driven Python script, executed as **`ariesgad`**, that integrates five distinct scanning and reconnaissance tools into a single interface. It combines pure Python (synchronous and asynchronous) with external Bash/Nmap commands.

**Author Name:** ♈️AriesGad♈️

## ⚠️ Critical Security Warning

The script uses external APIs for powerful reconnaissance (VirusTotal, Shodan, SecurityTrails). **Hardcoding API keys in the source code is a severe security risk.**

**Before running, you MUST open the `menu_scanner.py` file and replace the placeholder keys in the `--- Configuration & Global Variables ---` section with your actual keys.**

If the keys are left as placeholders, the corresponding API-based functions in Option 2 will be automatically skipped.

## Prerequisites

### 1. External Tools
Options 3 and 5 require the following command-line tools to be installed and accessible in your system's PATH:

* **`nmap`**: Used for fast ping scans and DNS resolution in **Option 5**.
* **`curl`**: Used for making web requests in the Bash script for **Option 3**.
* **`nslookup`**: Used for DNS checks in the Bash script for **Option 3**.

### 2. Python Environment
The script requires **Python 3.7+**. All necessary Python libraries are listed in `requirements.txt`.

## Setup and Installation

1.  **Save the script:** Save the provided Python code as **`menu_scanner.py`**.

2.  **Create requirements file:** Save the content of the `requirements.txt` above into a file named **`requirements.txt`** in the same directory.

3.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt

pip install requests aiohttp dnspython colorama tqdm


pip install requests aiohttp dnspython colorama tqdm aiodns


pip install aiodns

    
##installation

git clone https://github.com/AriesGad/ariesgad.git

cd ariesgad

chmod +x ariesgad.py

pip install -r requirements.txt

## Usage

```Run the script from your terminal:

python3 ariesgad.py


## install SecLists:

git clone https://github.com/danielmiessler/SecLists.git


# To run the Wordlist DNS Scan

```(Good for quick scans (5,000 words).

SecLists/Discovery/DNS/subdomains-top1million-5000.txt


```(​A classic subdomain list.)

SecLists/Discovery/DNS/fierce-hostlist.txt


```​(A very large, comprehensive list.)

SecLists/Discovery/DNS/dns-Jhaddix.txt