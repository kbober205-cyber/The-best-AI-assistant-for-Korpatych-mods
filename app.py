import os, json, zipfile, shutil, tempfile, uuid, re, sqlite3, secrets, hashlib, hmac
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Response, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import urllib.request, urllib.error

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
WORKSPACES = DATA / "workspaces"
DATA.mkdir(exist_ok=True)
WORKSPACES.mkdir(exist_ok=True)
DB = DATA / "x1.sqlite3"
app = FastAPI(title="ChatGPT X1 Mobile")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
API_KEY = os.getenv("OPENAI_API_KEY", "")
API_BASE = os.getenv("X1_API_BASE", "https://api.openai.com/v1").rstrip("/")
MODEL = os.getenv("X1_MODEL", "gpt-5")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
MAX_UPLOAD = 80 * 1024 * 1024

SYSTEM = """Ты — ChatGPT X1, помощник по разработке проектов и модов Minecraft Bedrock.
Работай только с переданными файлами проекта. Не утверждай, что изменил файл, если не вернул его содержимое в actions.
Для Minecraft Bedrock сохраняй совместимость Behavior Pack и Resource Pack, проверяй manifests, UUID, JSON и пути к ассетам.
Отвечай на русском, понятно и по делу.
Верни СТРОГО один JSON-объект без Markdown:
{"reply":"ответ пользователю","actions":[{"path":"относительный/путь/файла","content":"полное новое содержимое файла"}]}
Если изменения файлов не нужны, верни пустой массив actions. Не удаляй несвязанные файлы.
Не создавай абсолютные пути и пути с .. ."""


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS conversations(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, title TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, conversation_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, id);
        ''')
init_db()

def now(): return datetime.now(timezone.utc).isoformat()
def workspace(user_id: str) -> Path:
    p = WORKSPACES / user_id
    p.mkdir(parents=True, exist_ok=True)
    return p

def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260000).hex()

def current_user(request: Request):
    token = request.cookies.get('x1_session')
    if not token: raise HTTPException(401, 'Войди в аккаунт.')
    th = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row = c.execute('SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?', (th, now())).fetchone()
    if not row: raise HTTPException(401, 'Сессия истекла. Войди снова.')
    return dict(row)

def safe_path(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if root.resolve() not in p.parents and p != root.resolve(): raise ValueError('Недопустимый путь')
    return p

def list_files(root: Path):
    return [{'path':p.relative_to(root).as_posix(),'size':p.stat().st_size} for p in sorted(root.rglob('*')) if p.is_file()][:2000]

def tree_context(root: Path):
    rows=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file() or any(x in {'.git','__pycache__','node_modules'} for x in p.parts): continue
        rel=p.relative_to(root).as_posix()
        try:
            size=p.stat().st_size
            if size<=180000 and p.suffix.lower() in {'.json','.js','.ts','.mcfunction','.txt','.md','.lang','.material','.geo','.entity','.anim','.py'}:
                rows.append(f'\n--- {rel} ---\n{p.read_text(encoding="utf-8",errors="replace")[:12000]}')
            else: rows.append(f'\n--- {rel} [{size} bytes] ---')
        except Exception: pass
    return '\n'.join(rows)[:90000]

def api_call(messages):
    if not API_KEY: raise RuntimeError('На сервере не задан OPENAI_API_KEY. Владелец сайта должен добавить ключ в переменные окружения.')
    body=json.dumps({'model':MODEL,'input':messages}).encode()
    req=urllib.request.Request(API_BASE+'/responses',data=body,headers={'Authorization':f'Bearer {API_KEY}','Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=180) as r: data=json.loads(r.read().decode())
    except urllib.error.HTTPError as e: raise RuntimeError(f'Ошибка API ({e.code}): {e.read().decode("utf-8","replace")[:900]}')
    if data.get('output_text'): return data['output_text']
    return '\n'.join(x.get('text','') for item in data.get('output',[]) for x in item.get('content',[]) if x.get('type') in ('output_text','text')).strip()

class Credentials(BaseModel): username: str
class RegisterBody(Credentials): password: str
class LoginBody(Credentials): password: str
class ChatBody(BaseModel): message: str
class NewConversation(BaseModel): title: str = 'Новый чат'

@app.get('/')
def home(): return FileResponse(BASE/'static'/'index.html')

@app.get('/api/status')
def status(): return {'api_configured':bool(API_KEY),'model':MODEL}

@app.post('/api/register')
def register(body:RegisterBody, response:Response):
    username=body.username.strip().lower()
    if not re.fullmatch(r'[a-z0-9_]{3,24}',username): raise HTTPException(400,'Логин: 3–24 символа, только латинские буквы, цифры и _.')
    if len(body.password)<8: raise HTTPException(400,'Пароль должен содержать минимум 8 символов.')
    salt=secrets.token_bytes(16); uid=uuid.uuid4().hex
    try:
        with db() as c: c.execute('INSERT INTO users VALUES(?,?,?,?,?)',(uid,username,salt.hex(),hash_password(body.password,salt),now()))
    except sqlite3.IntegrityError: raise HTTPException(409,'Такой логин уже занят.')
    issue_session(uid,response)
    return {'ok':True,'username':username}

def issue_session(uid,response):
    token=secrets.token_urlsafe(36); th=hashlib.sha256(token.encode()).hexdigest()
    from datetime import timedelta
    expires=(datetime.now(timezone.utc)+timedelta(days=30)).isoformat()
    with db() as c: c.execute('INSERT INTO sessions VALUES(?,?,?)',(th,uid,expires))
    response.set_cookie('x1_session',token,httponly=True,samesite='lax',secure=COOKIE_SECURE,max_age=30*24*3600,path='/')

@app.post('/api/login')
def login(body:LoginBody,response:Response):
    with db() as c: user=c.execute('SELECT * FROM users WHERE username=?',(body.username.strip().lower(),)).fetchone()
    if not user or not hmac.compare_digest(hash_password(body.password,bytes.fromhex(user['salt'])),user['password_hash']): raise HTTPException(401,'Неверный логин или пароль.')
    issue_session(user['id'],response); return {'ok':True,'username':user['username']}

@app.post('/api/logout')
def logout(request:Request,response:Response,user=Depends(current_user)):
    token=request.cookies.get('x1_session','')
    with db() as c: c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie('x1_session',path='/'); return {'ok':True}

@app.get('/api/me')
def me(user=Depends(current_user)): return user

@app.get('/api/conversations')
def conversations(user=Depends(current_user)):
    with db() as c: rows=c.execute('SELECT id,title,created_at,updated_at FROM conversations WHERE user_id=? ORDER BY updated_at DESC LIMIT 100',(user['id'],)).fetchall()
    return {'conversations':[dict(x) for x in rows]}

@app.post('/api/conversations')
def new_conversation(body:NewConversation,user=Depends(current_user)):
    cid=uuid.uuid4().hex; title=body.title.strip()[:70] or 'Новый чат'; t=now()
    with db() as c: c.execute('INSERT INTO conversations VALUES(?,?,?,?,?)',(cid,user['id'],title,t,t))
    return {'id':cid,'title':title}

@app.get('/api/conversations/{cid}')
def get_conversation(cid:str,user=Depends(current_user)):
    with db() as c:
        conv=c.execute('SELECT id,title FROM conversations WHERE id=? AND user_id=?',(cid,user['id'])).fetchone()
        if not conv: raise HTTPException(404,'Чат не найден.')
        msgs=c.execute('SELECT role,content,created_at FROM messages WHERE conversation_id=? ORDER BY id',(cid,)).fetchall()
    return {'conversation':dict(conv),'messages':[dict(x) for x in msgs]}

@app.delete('/api/conversations/{cid}')
def delete_conversation(cid:str,user=Depends(current_user)):
    with db() as c:
        c.execute('DELETE FROM messages WHERE conversation_id=? AND user_id=?',(cid,user['id']))
        cur=c.execute('DELETE FROM conversations WHERE id=? AND user_id=?',(cid,user['id']))
        if not cur.rowcount: raise HTTPException(404,'Чат не найден.')
    return {'ok':True}

@app.post('/api/upload')
async def upload_project(file:UploadFile=File(...),user=Depends(current_user)):
    if not file.filename.lower().endswith('.zip'): raise HTTPException(400,'Загрузи ZIP-архив проекта.')
    root=workspace(user['id']); shutil.rmtree(root,ignore_errors=True); root.mkdir(parents=True,exist_ok=True)
    tmp=BASE/f'upload_{uuid.uuid4().hex}.zip'
    try:
        content=await file.read()
        if len(content)>MAX_UPLOAD: raise HTTPException(413,'Архив больше 80 МБ.')
        tmp.write_bytes(content)
        with zipfile.ZipFile(tmp) as z:
            for info in z.infolist():
                target=(root/info.filename).resolve()
                if root.resolve() not in target.parents and target!=root.resolve(): raise ValueError('Архив содержит небезопасный путь')
                if info.file_size>100*1024*1024: raise ValueError('В архиве найден слишком большой файл')
            z.extractall(root)
    except zipfile.BadZipFile: raise HTTPException(400,'Это не корректный ZIP-архив.')
    except ValueError as e: raise HTTPException(400,str(e))
    finally: tmp.unlink(missing_ok=True)
    return {'ok':True,'files':list_files(root)}

@app.get('/api/files')
def files(user=Depends(current_user)): return {'files':list_files(workspace(user['id']))}

@app.post('/api/chat')
def chat(body:ChatBody,user=Depends(current_user),conversation_id:str=''):
    prompt=body.message.strip()
    if not prompt: raise HTTPException(400,'Напиши сообщение.')
    with db() as c:
        if conversation_id:
            conv=c.execute('SELECT id,title FROM conversations WHERE id=? AND user_id=?',(conversation_id,user['id'])).fetchone()
            if not conv: raise HTTPException(404,'Чат не найден.')
            cid=conversation_id
        else:
            cid=uuid.uuid4().hex; t=now(); title=prompt[:48]
            c.execute('INSERT INTO conversations VALUES(?,?,?,?,?)',(cid,user['id'],title,t,t))
        prior=c.execute('SELECT role,content FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 12',(cid,)).fetchall()
        prior=list(reversed(prior))
    root=workspace(user['id']); context=tree_context(root)
    user_content=f'ФАЙЛЫ ПРОЕКТА:\n{context or "Проект пока не загружен."}\n\nЗАПРОС ПОЛЬЗОВАТЕЛЯ:\n{prompt}\n\nВерни JSON с reply и actions. Если проект не загружен, объясни, что нужно загрузить ZIP.'
    messages=[{'role':'system','content':SYSTEM}]+[{'role':x['role'],'content':x['content']} for x in prior]+[{'role':'user','content':user_content}]
    try:
        raw=api_call(messages); cleaned=re.sub(r'^```(?:json)?\s*|\s*```$','',raw.strip(),flags=re.I); match=re.search(r'\{.*\}',cleaned,re.S)
        if not match: reply=raw; changed=[]
        else:
            data=json.loads(match.group(0)); reply=str(data.get('reply','Готово.')); changed=[]
            for action in data.get('actions',[])[:30]:
                rel=str(action.get('path','')); content=action.get('content')
                if not rel or not isinstance(content,str) or '..' in Path(rel).parts or Path(rel).is_absolute(): continue
                dest=safe_path(root,rel); dest.parent.mkdir(parents=True,exist_ok=True); dest.write_text(content,encoding='utf-8'); changed.append(rel)
        with db() as c:
            t=now(); c.execute('INSERT INTO messages(conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?)',(cid,user['id'],'user',prompt,t)); c.execute('INSERT INTO messages(conversation_id,user_id,role,content,created_at) VALUES(?,?,?,?,?)',(cid,user['id'],'assistant',reply,t)); c.execute('UPDATE conversations SET updated_at=? WHERE id=?',(t,cid))
        return {'reply':reply,'changed':changed,'conversation_id':cid}
    except Exception as e: raise HTTPException(502,str(e))

@app.post('/api/build')
def build(user=Depends(current_user)):
    root=workspace(user['id']); files=list_files(root)
    if not files: raise HTTPException(400,'Сначала загрузи ZIP-проект.')
    errors=[]
    for p in root.rglob('*.json'):
        try: json.loads(p.read_text(encoding='utf-8'))
        except Exception as e: errors.append(f'{p.relative_to(root)}: {e}')
    staging=Path(tempfile.mkdtemp(prefix='x1_build_')); output=DATA/f'{user["id"]}_ChatGPT_X1_Mod.mcaddon'
    try:
        packs=[p for p in root.iterdir() if p.is_dir() and (p/'manifest.json').exists()]
        if packs:
            for pack in packs:
                with zipfile.ZipFile(staging/(pack.name+'.mcpack'),'w',zipfile.ZIP_DEFLATED) as z:
                    for f in pack.rglob('*'):
                        if f.is_file(): z.write(f,f.relative_to(pack))
        else:
            with zipfile.ZipFile(staging/'Project.mcpack','w',zipfile.ZIP_DEFLATED) as z:
                for f in root.rglob('*'):
                    if f.is_file(): z.write(f,f.relative_to(root))
        with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED) as z:
            for f in staging.rglob('*'):
                if f.is_file(): z.write(f,f.relative_to(staging))
    finally: shutil.rmtree(staging,ignore_errors=True)
    return {'ok':True,'download':'/api/download','json_errors':errors}

@app.get('/api/download')
def download(user=Depends(current_user)):
    path=DATA/f'{user["id"]}_ChatGPT_X1_Mod.mcaddon'
    if not path.exists(): raise HTTPException(404,'Сначала собери мод.')
    return FileResponse(path,filename='ChatGPT_X1_Mod.mcaddon',media_type='application/octet-stream')

@app.post('/api/reset')
def reset(user=Depends(current_user)):
    root=workspace(user['id']); shutil.rmtree(root,ignore_errors=True); root.mkdir(exist_ok=True); return {'ok':True}
