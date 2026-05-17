import http.server
import socketserver
import os
import shutil
import secrets
import hashlib
import hmac
from urllib.parse import urlparse, parse_qs

PORT = 8000
BIND_ADDR = '0.0.0.0'
UPLOAD_DIR = '.'

HIDDEN_FILES = {'index.py', 'index.html'}

PASSWORD = 'CHANGEME1234'
ACTIVE_SESSIONS: dict = {}

def _check_password(candidate: str) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(candidate.encode()).digest(),
        hashlib.sha256(PASSWORD.encode()).digest(),
    )

def _new_session_token() -> str:
    return secrets.token_hex(32)

def _is_authenticated(cookie_header: str) -> bool:
    if not cookie_header:
        return False
    for part in cookie_header.split(';'):
        part = part.strip()
        if part.startswith('session='):
            token = part[len('session='):]
            return token in ACTIVE_SESSIONS
    return False

def _safe_path(requested: str):
    upload_root = os.path.realpath(UPLOAD_DIR)
    clean = requested.lstrip('/')
    if clean.startswith('download/'):
        clean = clean[len('download/'):]
    if os.path.basename(clean) in HIDDEN_FILES:
        return None
    candidate = os.path.realpath(os.path.join(upload_root, clean))
    if candidate.startswith(upload_root + os.sep) or candidate == upload_root:
        return candidate
    return None

class UploadHandler(http.server.SimpleHTTPRequestHandler):

    def _set_session_cookie(self, token: str):
        self.send_header(
            'Set-Cookie',
            f'session={token}; HttpOnly; SameSite=Strict; Path=/'
        )

    def _clear_session_cookie(self):
        self.send_header(
            'Set-Cookie',
            'session=deleted; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
        )

    def _login_page(self, error: str = '') -> str:
        error_html = f'<p>{error}</p>' if error else ''
        return f'''
        <html>
        <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>LocalNAS - Login</title></head>
        <body>
            <h1>LocalNAS - Login</h1>
            <h2>Login</h2>
            {error_html}
            <form method="POST" action="/login">
                <input type="password" name="password" placeholder="Password" autofocus>
                <input type="submit" value="Login">
            </form>
            <hr>
<footer><small>Developed by jd5124682<br><a href="http://www.w3.org/html/logo/">
<img src="https://www.w3.org/html/logo/badge/html5-badge-h-device-storage.png" width="165" height="64" alt="HTML5 Powered with Device Access, and Offline &amp; Storage" title="HTML5 Powered with Device Access, and Offline &amp; Storage">
</a><br><a href="https://github.com/jd5124682/LocalNAS">Github Repository </a></small></footer>
        </body>
        </html>
        '''

    def _require_auth(self) -> bool:
        cookie = self.headers.get('Cookie', '')
        if not _is_authenticated(cookie):
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return False
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self._login_page().encode())
            return

        if path == '/logout':
            cookie = self.headers.get('Cookie', '')
            for part in cookie.split(';'):
                part = part.strip()
                if part.startswith('session='):
                    token = part[len('session='):]
                    ACTIVE_SESSIONS.pop(token, None)
            self.send_response(302)
            self._clear_session_cookie()
            self.send_header('Location', '/login')
            self.end_headers()
            return

        if not self._require_auth():
            return

        if path == '/explore':
            search_query = parse_qs(parsed.query).get('q', [''])[0].lower().strip()
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self._explorer_page(search_query).encode())
            return

        if path.startswith('/download/'):
            filename = path[len('/download/'):]
            safe = _safe_path(filename)
            if safe is None or not os.path.isfile(safe):
                self.send_error(404, 'File not found')
                return
            self._serve_file(safe)
            return

        if path == '/' or path == '/index.htm' or path == '/advanced_instructions.htm':
            super().do_GET()
            return

        self.send_error(403, 'Forbidden')

    def do_POST(self):
        if self.path == '/login':
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode(errors='replace')
            params = parse_qs(body)
            candidate = params.get('password', [''])[0]

            if _check_password(candidate):
                token = _new_session_token()
                ACTIVE_SESSIONS[token] = True
                self.send_response(302)
                self._set_session_cookie(token)
                self.send_header('Location', '/')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(self._login_page('Incorrect password.').encode())
            return

        if not self._require_auth():
            return

        if self.path == '/upload':
            content_type = self.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                self.send_error(400, 'Expected multipart/form-data')
                return

            boundary = content_type.split('boundary=')[-1].strip().encode()
            length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(length)

            parts = raw_body.split(b'--' + boundary)
            uploaded = []

            for part in parts:
                if b'filename=' not in part:
                    continue

                header_section, _, file_data = part.partition(b'\r\n\r\n')
                file_data = file_data.rstrip(b'\r\n')

                filename = None
                for line in header_section.decode(errors='ignore').splitlines():
                    if 'filename=' in line:
                        raw_name = line.split('filename=')[-1].strip().strip('"')
                        filename = os.path.basename(raw_name)
                        break

                if not filename or not file_data:
                    continue

                safe = _safe_path(filename)
                if safe is None:
                    continue

                with open(safe, 'wb') as f:
                    f.write(file_data)
                uploaded.append(filename)

            if uploaded:
                file_list = ''.join(f'<li>{f}</li>' for f in uploaded)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(
                    f'<p>Uploaded {len(uploaded)} file(s):</p>'
                    f'<ul>{file_list}</ul>'
                    f'<p><a href="index.htm">Back to Main menu</a></p>'.encode()
                )
            else:
                self.send_error(400, 'No valid files found in request')
            return

        self.send_error(405, 'Method not allowed')

    def _serve_file(self, abs_path: str):
        """Send a file from an absolute path that has already been validated."""
        try:
            size = os.path.getsize(abs_path)
            self.send_response(200)
            self.send_header('Content-Length', str(size))
            self.send_header('Content-Disposition',
                             f'attachment; filename="{os.path.basename(abs_path)}"')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()
            with open(abs_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
        except OSError:
            self.send_error(500, 'Could not read file')

    def _get_folder_size(self, folder):
        total = 0
        for root, dirs, files in os.walk(folder):
            for file in files:
                try:
                    total += os.path.getsize(os.path.join(root, file))
                except OSError:
                    pass
        return total

    def _explorer_page(self, search_query=''):
        try:
            localnas_size = self._get_folder_size(UPLOAD_DIR)
            total, used, free = shutil.disk_usage('.')
            storage_info = f'''
            <div>
                used: {self._human_size(localnas_size)}<br>
                remaining: {self._human_size(free)}
            </div>
            '''
        except Exception:
            storage_info = '<div>Storage info unavailable</div>'

        IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'}
        VIDEO_EXTS = {'.mp4', '.webm', '.ogg', '.mov', '.mkv', '.avi', '.m4v'}

        folder_counter = [0]
        rows = ''
        upload_root = os.path.realpath(UPLOAD_DIR)

        for root, dirs, files in os.walk(UPLOAD_DIR):
            dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
            level = os.path.relpath(root, UPLOAD_DIR)
            depth = 0 if level == '.' else level.count(os.sep) + 1
            folder_name = os.path.basename(root) if depth else 'LocalNAS Root'
            folder_id = f'folder_{folder_counter[0]}'
            folder_counter[0] += 1

            visible_files = [
                f for f in sorted(files)
                if f not in HIDDEN_FILES
                and not f.startswith('.')
                and (not search_query or search_query in f.lower())
            ]

            if not visible_files and search_query:
                continue

            indent_px = depth * 20
            is_open = (depth == 0 or bool(search_query))
            open_class = 'open' if is_open else ''
            arrow = 'v' if is_open else '>'

            rows += f'''
            <div class="folder">
                <div class="folder-header" onclick="toggleFolder('{folder_id}', this)">
                    <span class="arrow">{arrow}</span>
                    <span class="folder-icon">[+]</span>
                    <strong>{folder_name}</strong>
                    <span class="file-count">({len(visible_files)} file{"s" if len(visible_files) != 1 else ""})</span>
                </div>
                <div class="folder-contents {open_class}" id="{folder_id}">
            '''

            for file in visible_files:
                file_path = os.path.join(root, file)
                if not os.path.realpath(file_path).startswith(upload_root + os.sep):
                    continue
                size_str = self._human_size(os.path.getsize(file_path))
                safe_name = os.path.relpath(file_path, UPLOAD_DIR).replace('\\', '/')
                dl_url = f'/download/{safe_name}'
                ext = os.path.splitext(file)[1].lower()
                is_image = ext in IMAGE_EXTS
                is_video = ext in VIDEO_EXTS

                if is_image:
                    rows += f'''
                    <div class="file-row image-row" data-type="image" data-src="{dl_url}">
                        <span class="file-icon">[img]</span>
                        <a href="{dl_url}" class="file-link">{file}</a>
                        <span class="file-size">{size_str}</span>
                    </div>
                    '''
                elif is_video:
                    rows += f'''
                    <div class="file-row image-row" data-type="video" data-src="{dl_url}">
                        <span class="file-icon">[vid]</span>
                        <a href="{dl_url}" class="file-link">{file}</a>
                        <span class="file-size">{size_str}</span>
                    </div>
                    '''
                else:
                    rows += f'''
                    <div class="file-row">
                        <span class="file-icon">[-]</span>
                        <a href="{dl_url}" class="file-link">{file}</a>
                        <span class="file-size">{size_str}</span>
                    </div>
                    '''
            rows += '</div></div>'

        search_bar = f'''
            <form method="GET" action="/explore">
                <input type="text" name="q" value="{search_query}" placeholder="Search files...">
                <input type="submit" value="Search">
                {'<a href="/explore">Clear</a>' if search_query else ''}
            </form>
        '''

        explorer_style = ''

        explorer_js = '''
        <script>
        // Hide all collapsed folders on load
        document.querySelectorAll('.folder-contents').forEach(el => {
            if (!el.classList.contains('open')) el.style.display = 'none';
        });

        function toggleFolder(id, header) {
            const contents = document.getElementById(id);
            const arrow = header.querySelector('.arrow');
            const isOpen = contents.style.display === 'none';
            contents.style.display = isOpen ? '' : 'none';
            arrow.innerHTML = isOpen ? 'v' : '>';
        }

        const preview = document.getElementById('img-preview');
        const previewImg = document.getElementById('img-preview-img');
        const previewVid = document.getElementById('img-preview-vid');

        document.querySelectorAll('.image-row').forEach(row => {
            row.addEventListener('mouseenter', (e) => {
                const src = row.dataset.src;
                const type = row.dataset.type;
                if (type === 'video') {
                    previewImg.style.display = 'none';
                    previewVid.style.display = 'block';
                    if (previewVid.src !== location.origin + src) {
                        previewVid.src = src;
                        previewVid.load();
                        previewVid.play().catch(() => {});
                    }
                } else {
                    previewVid.style.display = 'none';
                    previewVid.pause();
                    previewVid.src = '';
                    previewImg.style.display = 'block';
                    previewImg.src = src;
                }
                preview.style.display = 'block';
                positionPreview(e);
            });
            row.addEventListener('mousemove', positionPreview);
            row.addEventListener('mouseleave', () => {
                preview.style.display = 'none';
                previewImg.src = '';
                previewVid.pause();
                previewVid.src = '';
            });
        });

        function positionPreview(e) {
            const pad = 16;
            const pw = preview.offsetWidth || 310;
            const ph = preview.offsetHeight || 310;
            let x = e.clientX + pad;
            let y = e.clientY + pad;
            if (x + pw > window.innerWidth) x = e.clientX - pw - pad;
            if (y + ph > window.innerHeight) y = e.clientY - ph - pad;
            preview.style.left = x + 'px';
            preview.style.top = y + 'px';
        }
        </script>
        '''

        return f'''
        <html>
        <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>LocalNAS - Explore</title></head>
        <body>
            <a href="index.htm"><h1>LocalNAS - Explore</h1></a>
            {storage_info}
            {search_bar}
            <div style="text-align:left;">
                {rows}
            </div>
            {explorer_js}
            <hr>
<footer><small>Developed by jd5124682<br><a href="http://www.w3.org/html/logo/">
<img src="https://www.w3.org/html/logo/badge/html5-badge-h-device-storage.png" width="165" height="64" alt="HTML5 Powered with Device Access, and Offline &amp; Storage" title="HTML5 Powered with Device Access, and Offline &amp; Storage">
</a><br><a href="https://github.com/jd5124682/LocalNAS">Github Repository </a></small></footer>
        </body>
        </html>
        '''

    def _human_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} PB'


with socketserver.TCPServer((BIND_ADDR, PORT), UploadHandler) as httpd:
    print(f'Serving at http://{BIND_ADDR}:{PORT}')
    httpd.serve_forever()
