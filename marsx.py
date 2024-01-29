import socket
from datetime import datetime
import argparse

def marsx_logo():
    print("\033[1;31m    (  \/  )  /__\  (  _ \/ __)( \/ ) \033[0m")
    print("\033[1;31m     )    (  /(__)\  )   /\__ \ )  (   \033[0m")
    print("\033[1;31m     (_/\/\_)(__)(__)(_)\_)(___/(_/\_) \033[0m")
    print("\nMarsX Port Tarama Ve Güvenlik Açıkları By:Darkmarsx\n")

def show_help(parser):
    marsx_logo()
    print("\n\033[1;36mKullanım:\033[0m")
    print("  \033[1;36mpython marsx.py --target <Hedef> --start-port <Başlangıç Portu> --end-port <Bitiş Portu>\033[0m")
    print("\n\033[1;36mTüm portları taramak için:\033[0m")
    print("  \033[1;36mpython marsx.py --target <Hedef> --all-ports\033[0m")
    print("\n\033[1;36mÖzel Komut Satırı:\033[0m")
    print("  \033[1;36mpython marsx.py --marsx-command\033[0m")

def scan_ports(target, start_port, end_port, verbose=False, proxy=None):
    open_ports = []
    potential_risk_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443]

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if proxy:
            sock.set_proxy(socket.SOCKS5, proxy)

        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            if port in potential_risk_ports:
                print("\033[1;33m[!] Port {} may be vulnerable to attacks and could be a potential risk.\033[0m".format(port))
            print("\033[1;32m[*] Port {} is open.\033[0m".format(port))
        sock.close()

    return open_ports

def classify_ports(ports):
    high_risk_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443]
    medium_risk_ports = [x for x in range(1024, 49152)]
    
    high_risk = list(set(ports).intersection(high_risk_ports))
    medium_risk = list(set(ports).intersection(medium_risk_ports))
    low_risk = list(set(ports) - set(high_risk) - set(medium_risk))
    
    return {'High Risk': high_risk, 'Medium Risk': medium_risk, 'Low Risk': low_risk}

def port_info(port):
    try:
        service = socket.getservbyport(port)
        print("\033[1;34m[*] Port {} - Service: {}\033[0m".format(port, service))
    except:
        print("\033[1;34m[*] Port {} - Service: Unknown\033[0m".format(port))

def save_to_file(filename, content):
    with open(filename, 'w') as file:
        file.write(content)

def marsx_command():
    print("\n\033[1;36mMarsX Özel Komut Satırı:\033[0m")
    print("  \033[1;36m--marsx-command\033[0m     MarsX programına özel komut satırını çalıştırır.")
    print("  \033[1;36m--example-param\033[0m     Özel bir parametre ekleyebilirsiniz.")

def main():
    parser = argparse.ArgumentParser(description="MarsX Port Tarama ve Güvenlik Değerlendirme Programı")
    parser.add_argument("--target", help="Hedef IP adresi veya domain", required=True)
    parser.add_argument("--start-port", type=int, help="Başlangıç portu", required=True)
    parser.add_argument("--end-port", type=int, help="Bitiş portu", required=True)
    parser.add_argument("--all-ports", action="store_true", help="Tüm portları tarar")
    parser.add_argument("--output", help="Sonuçları belirtilen dosyaya kaydeder")
    parser.add_argument("--verbose", action="store_true", help="Detaylı çıktıları görüntüler")
    parser.add_argument("--proxy", action="store_true", help="Proxy kullanımını etkinleştirir")
    parser.add_argument("--marsx-command", action="store_true", help="MarsX programına özel komut satırını çalıştırır")

    args = parser.parse_args()

    try:
        marsx_logo()

        if args.marsx_command:
            marsx_command()
            return

        start_time = datetime.now()
        open_ports = scan_ports(args.target, args.start_port, args.end_port, args.verbose, args.proxy) if not args.all_ports else scan_ports(args.target, 1, 65535, args.verbose, args.proxy)
        end_time = datetime.now()
        elapsed_time = end_time - start_time

        result_text = "\nTarama {:.2f} saniyede tamamlandı.\nAçık portlar: {}".format(elapsed_time.total_seconds(), open_ports)
        print(result_text)

        classification = classify_ports(open_ports)
        classification_text = "\nSınıflandırma:\nYüksek Riskli Portlar: {}\nOrta Riskli Portlar: {}\nDüşük Riskli Portlar: {}".format(classification['High Risk'], classification['Medium Risk'], classification['Low Risk'])
        print(classification_text)

        for port in open_ports:
            port_info(port)

        full_result = result_text + classification_text
        if args.output:
            save_to_file(args.output, full_result)
            print("\nSonuçlar {} dosyasına kaydedildi.".format(args.output))

    except Exception as e:
        print("Bir hata oluştu: {}".format(str(e)))

if __name__ == "__main__":
    main()
    