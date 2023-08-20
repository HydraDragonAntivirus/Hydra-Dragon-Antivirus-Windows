import os
import hashlib
import multiprocessing
import subprocess
import ctypes
import psutil
import tkinter as tk
from tkinter import messagebox
import sys
import ctypes 

def is_file_infected_md5(md5):
    md5_connection = sqlite3.connect("MD5basedatabase.db")
    main_connection = sqlite3.connect("main.db")
    daily_connection = sqlite3.connect("daily.db")
    old_virus_base_connection = sqlite3.connect("oldvirusbase.db")
    virus_base_connection = sqlite3.connect("virusbase.db")
    full_md5_connection = sqlite3.connect("Hash.db")
    
    # Check in the MD5base table
    md5_command = md5_connection.execute("SELECT COUNT(*) FROM MD5base WHERE field1 = ?;", (md5,))
    md5_result = md5_command.fetchone()[0]
    if md5_result > 0:
        md5_connection.close()
        return True
    
    # Check in the main table
    main_command = main_connection.execute("SELECT COUNT(*) FROM main WHERE field2 = ?;", (md5,))
    main_result = main_command.fetchone()[0]
    if main_result > 0:
        main_connection.close()
        return True
    
    # Check in the daily table
    daily_command = daily_connection.execute("SELECT COUNT(*) FROM daily WHERE field2 = ?;", (md5,))
    daily_result = daily_command.fetchone()[0]
    if daily_result > 0:
        daily_connection.close()
        return True
    
    # Check in the oldvirusbase table
    old_virus_base_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase WHERE field2 = ?;", (md5,))
    old_virus_base_result = old_virus_base_command.fetchone()[0]
    if old_virus_base_result > 0:
        old_virus_base_connection.close()
        return True
    
    # Check in the oldvirusbase2 table
    old_virus_base2_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase2 WHERE field1 = ?;", (md5,))
    old_virus_base2_result = old_virus_base2_command.fetchone()[0]
    if old_virus_base2_result > 0:
        old_virus_base_connection.close()
        return True
    
    # Check in the oldvirusbase3 table
    old_virus_base3_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase3 WHERE field2 = ?;", (md5,))
    old_virus_base3_result = old_virus_base3_command.fetchone()[0]
    if old_virus_base3_result > 0:
        old_virus_base_connection.close()
        return True
    
    # Check in the virusbase table
    virus_base_command = virus_base_connection.execute("SELECT COUNT(*) FROM virusbase WHERE field1 = ?;", (md5,))
    virus_base_result = virus_base_command.fetchone()[0]
    if virus_base_result > 0:
        virus_base_connection.close()
        return True
    
    # Check in the virusbase2 table
    virus_base2_command = virus_base_connection.execute("SELECT COUNT(*) FROM virusbase2 WHERE field1 = ?;", (md5,))
    virus_base2_result = virus_base2_command.fetchone()[0]
    if virus_base2_result > 0:
        virus_base_connection.close()
        return True
    
    # Check in the HashDB table
    full_md5_command = full_md5_connection.execute("SELECT COUNT(*) FROM HashDB WHERE hash = ?;", (md5,))
    full_md5_result = full_md5_command.fetchone()[0]
    if full_md5_result > 0:
        full_md5_connection.close()
        return True
    
    md5_connection.close()
    main_connection.close()
    daily_connection.close()
    old_virus_base_connection.close()
    virus_base_connection.close()
    full_md5_connection.close()
    return False
def is_file_infected_sha1(sha1):
    # Check in the SHA256hashes database for SHA1 hashes
    database_path_sha256_hashes = "SHA256hashes.db"
    connection_sha256_hashes = sqlite3.connect(database_path_sha256_hashes)

    sha1_command_text = "SELECT EXISTS(SELECT 1 FROM malwarescomsha1 WHERE field1 = ? LIMIT 1);"
    sha1_result = connection_sha256_hashes.execute(sha1_command_text, (sha1,)).fetchone()

    if sha1_result and sha1_result[0]:
        connection_sha256_hashes.close()
        return True

    # If the SHA1 hash was not found in the SHA256hashes.db database,
    # Check in the abusech.db database for SHA1 hashes in SSLBL table with field2.
    database_path_abusech = "abusech.db"
    connection_abusech = sqlite3.connect(database_path_abusech)

    sslbl_command_text = "SELECT EXISTS(SELECT 1 FROM SSLBL WHERE field2 = ? LIMIT 1);"
    sslbl_result = connection_abusech.execute(sslbl_command_text, (sha1,)).fetchone()

    connection_abusech.close()

    if sslbl_result and sslbl_result[0]:
        return True
    # If the code reaches this point, it means the SHA1 hash was not found in both databases.
    return False

def is_file_infected_sha256(sha256):
    database_path_0 = "batchvirusbase.db"
    database_path_sha256 = "SHA256databasesqlite.db"
    database_path_fake_domain = "vxugfakedomain.db"
    database_path_sha256_hashes = "SHA256hashes.db"
    database_path_emotet_ioc = "IOC_Emotet.db"  # New database path
    database_path_full_sha256 = "full_sha256.db"  # New database path
    database_path_abusech = "abusech.db"  # New database path

    # Check in the SHA256 table
    connection = sqlite3.connect(database_path_0)

    sha256_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256 WHERE field1 = ? LIMIT 1) FROM SHA256 WHERE field1 = ?;"
    sha256_result = connection.execute(sha256_command_text, (sha256, sha256)).fetchone()

    if sha256_result and sha256_result[0]:
        connection.close()
        return True, ""

    # Check in the abusech database
    connection_abusech = sqlite3.connect(database_path_abusech)

    abusech_command_text = "SELECT EXISTS(SELECT 1 FROM full_sha256 WHERE field3 = ? LIMIT 1) FROM full_sha256 WHERE field3 = ?;"
    abusech_result = connection_abusech.execute(abusech_command_text, (sha256, sha256)).fetchone()

    connection_abusech.close()

    if abusech_result and abusech_result[0]:
        return True

    # Check in the full_sha256 database
    connection_full_sha256 = sqlite3.connect(database_path_full_sha256)

    full_sha256_command_text = "SELECT EXISTS(SELECT 1 FROM full_sha256 WHERE field1 = ? LIMIT 1) FROM full_sha256 WHERE field1 = ?;"
    full_sha256_result = connection_full_sha256.execute(full_sha256_command_text, (sha256, sha256)).fetchone()

    connection_full_sha256.close()

    if full_sha256_result and full_sha256_result[0]:
        return True

    # Check in the SHA256 database
    connection_sha256 = sqlite3.connect(database_path_sha256)

    sha256_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256 WHERE field1 = ? LIMIT 1) FROM SHA256 WHERE field1 = ?;"
    sha256_result = connection_sha256.execute(sha256_command_text, (sha256, sha256)).fetchone()

    connection_sha256.close()

    if sha256_result and sha256_result[0]:
        return True

    # Check in the vxugfakedomain database
    connection_fake_domain = sqlite3.connect(database_path_fake_domain)

    fake_domain_command_text = "SELECT EXISTS(SELECT 1 FROM vxugfakedomain WHERE field5 = ? LIMIT 1) FROM vxugfakedomain WHERE field5 = ?;"
    fake_domain_result = connection_fake_domain.execute(fake_domain_command_text, (sha256, sha256)).fetchone()

    connection_fake_domain.close()

    if fake_domain_result and fake_domain_result[0]:
        return True

    # Check in the SHA256hashes database
    connection_sha256_hashes = sqlite3.connect(database_path_sha256_hashes)

    sha256_hashes_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256hashes WHERE field1 = ? LIMIT 1) FROM SHA256hashes WHERE field1 = ?;"
    sha256_hashes_result = connection_sha256_hashes.execute(sha256_hashes_command_text, (sha256, sha256)).fetchone()

    connection_sha256_hashes.close()

    if sha256_hashes_result and sha256_hashes_result[0]:
        return True

    # Check in the Emotet IOC database
    connection_emotet_ioc = sqlite3.connect(database_path_emotet_ioc)  # New database connection

    emotet_ioc_command_text = "SELECT EXISTS(SELECT 1 FROM IOC_Emotet WHERE field1 = ? LIMIT 1) FROM IOC_Emotet WHERE field1 = ?;"  # New table and field names
    emotet_ioc_result = connection_emotet_ioc.execute(emotet_ioc_command_text, (sha256, sha256)).fetchone()

    connection_emotet_ioc.close()

    if emotet_ioc_result and emotet_ioc_result[0]:
        return True

    # If the code reaches this point, it means the record with the specified field1 value was not found in any of the databases.
    return False

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def calculate_sha1(file_path):
    hash_sha1 = hashlib.sha1()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()
def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()
def scan_folder_with_clamscan(folder_path):
    try:
        subprocess.run(["cmd", "/k", "clamscan.exe", "-r", "--heuristic-alerts=yes", "--kill", "--remove=yes", "--detect-pua=yes", "--normalize=no", folder_path])
    except Exception as e:
        print(f"Error running ClamScan: {e}")
def delete_file(file_path):
    try:
        os.remove(file_path)
        return f"Infected file deleted: {file_path}"
    except Exception as e:
        return f"Error deleting {file_path}: {e}"

def scan_folder_parallel(folder_path):
    infected_files = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        file_paths = [os.path.join(root, file) for root, _, files in os.walk(folder_path) for file in files]
        results = executor.map(scan_file, file_paths)
        
        for result in results:
            if result and result.startswith("Infected"):
                infected_files.append(result)
            elif result:
                print(result)
    
    if infected_files:
        print("\nInfected files:")
        for infected_file in infected_files:
            print(infected_file)
    else:
        print("\nNo infected files found.")    
import os
import subprocess
import hashlib
import sqlite3
import tkinter as tk
from tkinter import filedialog
import concurrent.futures
import psutil 

def is_file_infected_md5(md5):
    md5_connection = sqlite3.connect("MD5basedatabase.db")
    main_connection = sqlite3.connect("main.db")
    daily_connection = sqlite3.connect("daily.db")
    old_virus_base_connection = sqlite3.connect("oldvirusbase.db")
    virus_base_connection = sqlite3.connect("virusbase.db")
    full_md5_connection = sqlite3.connect("Hash.db")
    
    # Check in the MD5base table
    md5_command = md5_connection.execute("SELECT COUNT(*) FROM MD5base WHERE field1 = ?;", (md5,))
    md5_result = md5_command.fetchone()[0]
    if md5_result > 0:
        md5_connection.close()
        return True
    
    # Check in the main table
    main_command = main_connection.execute("SELECT COUNT(*) FROM main WHERE field2 = ?;", (md5,))
    main_result = main_command.fetchone()[0]
    if main_result > 0:
        main_connection.close()
        return True
    
    # Check in the daily table
    daily_command = daily_connection.execute("SELECT COUNT(*) FROM daily WHERE field2 = ?;", (md5,))
    daily_result = daily_command.fetchone()[0]
    if daily_result > 0:
        daily_connection.close()
        return True
    
    # Check in the oldvirusbase table
    old_virus_base_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase WHERE field2 = ?;", (md5,))
    old_virus_base_result = old_virus_base_command.fetchone()[0]
    if old_virus_base_result > 0:
        old_virus_base_connection.close()
        return True
    
    # Check in the oldvirusbase2 table
    old_virus_base2_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase2 WHERE field1 = ?;", (md5,))
    old_virus_base2_result = old_virus_base2_command.fetchone()[0]
    if old_virus_base2_result > 0:
        old_virus_base_connection.close()
        return True
    
    # Check in the oldvirusbase3 table
    old_virus_base3_command = old_virus_base_connection.execute("SELECT COUNT(*) FROM oldvirusbase3 WHERE field2 = ?;", (md5,))
    old_virus_base3_result = old_virus_base3_command.fetchone()[0]
    if old_virus_base3_result > 0:
        old_virus_base_connection.close()
        return True
    
    # Check in the virusbase table
    virus_base_command = virus_base_connection.execute("SELECT COUNT(*) FROM virusbase WHERE field1 = ?;", (md5,))
    virus_base_result = virus_base_command.fetchone()[0]
    if virus_base_result > 0:
        virus_base_connection.close()
        return True
    
    # Check in the virusbase2 table
    virus_base2_command = virus_base_connection.execute("SELECT COUNT(*) FROM virusbase2 WHERE field1 = ?;", (md5,))
    virus_base2_result = virus_base2_command.fetchone()[0]
    if virus_base2_result > 0:
        virus_base_connection.close()
        return True
    
    # Check in the HashDB table
    full_md5_command = full_md5_connection.execute("SELECT COUNT(*) FROM HashDB WHERE hash = ?;", (md5,))
    full_md5_result = full_md5_command.fetchone()[0]
    if full_md5_result > 0:
        full_md5_connection.close()
        return True
    
    md5_connection.close()
    main_connection.close()
    daily_connection.close()
    old_virus_base_connection.close()
    virus_base_connection.close()
    full_md5_connection.close()
    return False
def is_file_infected_sha1(sha1):
    # Check in the SHA256hashes database for SHA1 hashes
    database_path_sha256_hashes = "SHA256hashes.db"
    connection_sha256_hashes = sqlite3.connect(database_path_sha256_hashes)

    sha1_command_text = "SELECT EXISTS(SELECT 1 FROM malwarescomsha1 WHERE field1 = ? LIMIT 1);"
    sha1_result = connection_sha256_hashes.execute(sha1_command_text, (sha1,)).fetchone()

    if sha1_result and sha1_result[0]:
        connection_sha256_hashes.close()
        return True

    # If the SHA1 hash was not found in the SHA256hashes.db database,
    # Check in the abusech.db database for SHA1 hashes in SSLBL table with field2.
    database_path_abusech = "abusech.db"
    connection_abusech = sqlite3.connect(database_path_abusech)

    sslbl_command_text = "SELECT EXISTS(SELECT 1 FROM SSLBL WHERE field2 = ? LIMIT 1);"
    sslbl_result = connection_abusech.execute(sslbl_command_text, (sha1,)).fetchone()

    connection_abusech.close()

    if sslbl_result and sslbl_result[0]:
        return True
    # If the code reaches this point, it means the SHA1 hash was not found in both databases.
    return False

def is_file_infected_sha256(sha256):
    database_path_0 = "batchvirusbase.db"
    database_path_sha256 = "SHA256databasesqlite.db"
    database_path_fake_domain = "vxugfakedomain.db"
    database_path_sha256_hashes = "SHA256hashes.db"
    database_path_emotet_ioc = "IOC_Emotet.db"  # New database path
    database_path_full_sha256 = "full_sha256.db"  # New database path
    database_path_abusech = "abusech.db"  # New database path

    # Check in the SHA256 table
    connection = sqlite3.connect(database_path_0)

    sha256_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256 WHERE field1 = ? LIMIT 1) FROM SHA256 WHERE field1 = ?;"
    sha256_result = connection.execute(sha256_command_text, (sha256, sha256)).fetchone()

    if sha256_result and sha256_result[0]:
        connection.close()
        return True, ""

    # Check in the abusech database
    connection_abusech = sqlite3.connect(database_path_abusech)

    abusech_command_text = "SELECT EXISTS(SELECT 1 FROM full_sha256 WHERE field3 = ? LIMIT 1) FROM full_sha256 WHERE field3 = ?;"
    abusech_result = connection_abusech.execute(abusech_command_text, (sha256, sha256)).fetchone()

    connection_abusech.close()

    if abusech_result and abusech_result[0]:
        return True

    # Check in the full_sha256 database
    connection_full_sha256 = sqlite3.connect(database_path_full_sha256)

    full_sha256_command_text = "SELECT EXISTS(SELECT 1 FROM full_sha256 WHERE field1 = ? LIMIT 1) FROM full_sha256 WHERE field1 = ?;"
    full_sha256_result = connection_full_sha256.execute(full_sha256_command_text, (sha256, sha256)).fetchone()

    connection_full_sha256.close()

    if full_sha256_result and full_sha256_result[0]:
        return True

    # Check in the SHA256 database
    connection_sha256 = sqlite3.connect(database_path_sha256)

    sha256_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256 WHERE field1 = ? LIMIT 1) FROM SHA256 WHERE field1 = ?;"
    sha256_result = connection_sha256.execute(sha256_command_text, (sha256, sha256)).fetchone()

    connection_sha256.close()

    if sha256_result and sha256_result[0]:
        return True

    # Check in the vxugfakedomain database
    connection_fake_domain = sqlite3.connect(database_path_fake_domain)

    fake_domain_command_text = "SELECT EXISTS(SELECT 1 FROM vxugfakedomain WHERE field5 = ? LIMIT 1) FROM vxugfakedomain WHERE field5 = ?;"
    fake_domain_result = connection_fake_domain.execute(fake_domain_command_text, (sha256, sha256)).fetchone()

    connection_fake_domain.close()

    if fake_domain_result and fake_domain_result[0]:
        return True

    # Check in the SHA256hashes database
    connection_sha256_hashes = sqlite3.connect(database_path_sha256_hashes)

    sha256_hashes_command_text = "SELECT EXISTS(SELECT 1 FROM SHA256hashes WHERE field1 = ? LIMIT 1) FROM SHA256hashes WHERE field1 = ?;"
    sha256_hashes_result = connection_sha256_hashes.execute(sha256_hashes_command_text, (sha256, sha256)).fetchone()

    connection_sha256_hashes.close()

    if sha256_hashes_result and sha256_hashes_result[0]:
        return True

    # Check in the Emotet IOC database
    connection_emotet_ioc = sqlite3.connect(database_path_emotet_ioc)  # New database connection

    emotet_ioc_command_text = "SELECT EXISTS(SELECT 1 FROM IOC_Emotet WHERE field1 = ? LIMIT 1) FROM IOC_Emotet WHERE field1 = ?;"  # New table and field names
    emotet_ioc_result = connection_emotet_ioc.execute(emotet_ioc_command_text, (sha256, sha256)).fetchone()

    connection_emotet_ioc.close()

    if emotet_ioc_result and emotet_ioc_result[0]:
        return True

    # If the code reaches this point, it means the record with the specified field1 value was not found in any of the databases.
    return False

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def calculate_sha1(file_path):
    hash_sha1 = hashlib.sha1()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha1.update(chunk)
    return hash_sha1.hexdigest()
def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()
def scan_folder_with_clamscan(folder_path):
    try:
        subprocess.run(["cmd", "/k", "clamscan.exe", "-r", "--heuristic-alerts=yes", "--kill", "--remove=yes", "--detect-pua=yes", "--normalize=no", folder_path])
    except Exception as e:
        print(f"Error running ClamScan: {e}")
def delete_file(file_path):
    try:
        os.remove(file_path)
        return f"Infected file deleted: {file_path}"
    except Exception as e:
        return f"Error deleting {file_path}: {e}"
def scan_file(file_path):
    try:
        file_size = os.path.getsize(file_path)
        
        # Skip empty files
        if file_size == 0:
            return f"Clean file: {file_path}"
        
        # Calculate hash values
        md5 = calculate_md5(file_path)
        sha1 = calculate_sha1(file_path)
        sha256 = calculate_sha256(file_path)
        
        # Check if the file is infected using hash-based methods
        if is_file_infected_md5(md5) or is_file_infected_sha1(sha1) or is_file_infected_sha256(sha256):
            print(f"Infected file detected: {file_path}\nMD5 Hash: {md5}")
            delete_result = delete_file(file_path)  # Automatically delete infected file
            if delete_result.startswith("Infected file deleted"):
                return f"Infected file deleted: {file_path}"
            else:
                return f"Error deleting infected file: {file_path}"
        else:
            return f"Clean file: {file_path}"
        
    except PermissionError:
        return f"Access denied: {file_path}"
    except Exception as e:
        return f"Error processing {file_path}: {e}"

def scan_folder_parallel(folder_path):
    infected_files = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        file_paths = [os.path.join(root, file) for root, _, files in os.walk(folder_path) for file in files]
        results = executor.map(scan_file, file_paths)
        
        for result in results:
            if result and result.startswith("Infected"):
                infected_files.append(result)
            elif result:
                print(result)
    
    if infected_files:
        print("\nInfected files:")
        for infected_file in infected_files:
            print(infected_file)
    else:
        print("\nNo infected files found.") 
        # Function to calculate hash value of a file
def calculate_hash(data, hash_func):
    hash_obj = hash_func()
    hash_obj.update(data)
    return hash_obj.hexdigest()
def run_as_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e:
        print("Error:", e)

def main0():
    if os.name == "nt" and ctypes.windll.shell32.IsUserAnAdmin() == 0:
        print("Administrator permissions required. Re-running as administrator...")
        run_as_admin()
        return
    
    # Burada yönetici izni gerektirmeyen iþlemi gerçekleþtirin
    print("Running with administrator permissions or on a non-Windows platform.")

def get_running_process_file_paths():
    process_file_paths = []
    for process in psutil.process_iter(attrs=['pid', 'name', 'exe']):
        try:
            process_exe = process.info['exe']
            if process_exe and os.path.exists(process_exe):
                process_file_paths.append(process_exe)
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    return process_file_paths

def scan_files_with_clamscan(file_paths):
    try:
        for file_path in file_paths:
            subprocess.run(["clamscan", file_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error while scanning {file_path}: {e}")

def get_running_processes_and_hashes():
    try:
        while True:
            running_processes = psutil.process_iter(attrs=['pid', 'name', 'exe'])
            for process in running_processes:
                try:
                    process_name = process.info['name']
                    process_exe = process.info['exe']
                    if process_exe and os.path.exists(process_exe):
                        file_size = os.path.getsize(process_exe)
                        if file_size > 0:
                            with open(process_exe, "rb") as file:
                                data = file.read()
                                md5_hash = calculate_hash(data, hashlib.md5)
                                sha1_hash = calculate_hash(data, hashlib.sha1)
                                sha256_hash = calculate_hash(data, hashlib.sha256)
                                print(f"Process: {process_name}\nMD5: {md5_hash}\nSHA-1: {sha1_hash}\nSHA-256: {sha256_hash}\n")
                        else:
                            print(f"Process: {process_name}\nEmpty file, skipping...\n")
                            continue  # Skip to the next process
                except (PermissionError, FileNotFoundError, ProcessLookupError):
                    pass  # Skip permission errors, missing files, and process lookup errors
                except Exception as e:
                    print(f"Error processing process {process_name}: {e}")
    except KeyboardInterrupt:
        print("Process list and hash calculation stopped.")
def get_running_files():
    running_files = []

    running_processes = psutil.process_iter(attrs=['pid', 'name', 'exe'])
    for process in running_processes:
        try:
            process_exe = process.info['exe']
            if process_exe and os.path.exists(process_exe):
                running_files.append(process_exe)
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass

    return running_files

def scan_running_files_with_clamscan():
    try:
        running_files = get_running_files()

        if running_files:
            subprocess.run(["clamscan"] + running_files, check=True)
        else:
            print("No running files to scan.")

    except subprocess.CalledProcessError as e:
        print(f"Error while scanning: {e}")
    except Exception as e:
        print(f"Error: {e}")
def main():
    user_choice = input("Select an option:\n1. Scan a folder\n2. Scan running processes\nEnter option number: ")

    if user_choice == "1":
        folder_path = input("Enter the path of the folder to scan: ")
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            print(f"Scanning folder: {folder_path} with ClamScan...")

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_clamscan = executor.submit(scan_folder_with_clamscan, folder_path)

                future_clamscan.result()

        else:
            print("Invalid folder path.")

    elif user_choice == "2":
        print("Scanning running processes with ClamScan...")
        scan_running_files_with_clamscan()

    else:
        print("Invalid option.")
if __name__ == "__main__":
        main0()    
        main() 