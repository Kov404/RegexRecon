#!/usr/bin/env python3
import concurrent.futures
import requests
import re
import argparse

class Regex:
    def __init__(self, urlsRegex, regex_file, userAgent,thread):
        self.urlsRegex = urlsRegex
        self.regex_file = regex_file
        self.userAgent = userAgent
        self.threads = thread

    def verificaAPIS_Regex(self):
        regex_list = []

        aws_gcp_azure_regexes = [
            r'AKIA[0-9A-Z]{16}',
            #r'[A-Za-z0-9/+=]{40}',
            r'AIza[0-9A-Za-z-_]{35}',
            #r'[A-Za-z0-9/+=]{16,}',
            r'\d{12}',
            r"(apikey|APIKEY)[\s]*[:=]+[\s]*[\"\']?[0-9A-Za-z\-]{5,100}[\"\']?",
            r'(?:https://)?(?:[a-zA-Z0-9_\-]+)\.blob\.core\.windows\.net',
        ]

        with open(self.urlsRegex, "r") as file:
            lines = file.readlines()

        if self.regex_file:
            with open(self.regex_file, "r") as file:
                regex_list = [line.strip() for line in file.readlines()]

        def check_and_log(matches, regex, output_file):
            match_found = False
            for match_num, match in enumerate(matches, start=1):
                match_found = True
                print(f"Regex: {regex}")
                print(f"Match {match_num} found: {match.group()}")
                with open(output_file, 'a') as out_file:
                    log_lines = [
                        #f"IP: {ip}\n", 
                        f"URL: {line}\n", 
                        f"Regex: {regex}\n", 
                        f"Match {match_num}: {match.group()}\n\n"
                    ]
                    out_file.writelines(log_lines)
            return match_found

        for line in lines:
            ip = line.strip()
            print(ip)
            header = {'User-Agent': self.userAgent}
            proxy = {'http': 'http://127.0.0.1:8080'}

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=int(self.threads)) as executor:
                    future = executor.submit(requests.get, ip, headers=header, proxies=proxy)
                    result_text = future.result().text

                # Verificar regexes do arquivo
                for regex in regex_list:
                    check_and_log(re.finditer(regex, result_text, re.MULTILINE), regex, 'results_regexes.txt')

                # Verificar regexes de AWS, GCP e Azure
                for regex in aws_gcp_azure_regexes:
                    check_and_log(re.finditer(regex, result_text, re.MULTILINE), regex, 'Regex_clouds.txt')

            except requests.exceptions.RequestException as e:
                print(f"Erro ao fazer requisição para {ip}: {e}")
                with open('out.txt', 'a') as out_file:
                    out_file.write(f"Erro ao fazer requisição para {ip}: {e}\n")
            except Exception as e:
                print(f"Erro ao processar {ip}: {e}")
                with open('out.txt', 'a') as out_file:
                    out_file.write(f"Erro ao processar {ip}: {e}\n")

def main():
    parser = argparse.ArgumentParser(description="Verificador de APIs em arquivos Regex")
    parser.add_argument('-f', '--file', required=True, help="Caminho para o arquivo de URLs Regex")
    parser.add_argument('-r', '--regex', help="Caminho para o arquivo de regex")
    parser.add_argument('-t', '--threads', default='10', help="Quantidade de threads a ser utilizado")
    parser.add_argument('-a', '--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36', help="User-Agent a ser utilizado nas requisições")



    args = parser.parse_args()
    urlsRegex = args.file
    regex_file = args.regex
    userAgent = args.user_agent
    thread = args.threads

    regex = Regex(urlsRegex, regex_file, userAgent,thread)
    regex.verificaAPIS_Regex()

if __name__ == "__main__":
    main()
