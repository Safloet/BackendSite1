from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
from urllib.parse import quote, unquote

app = FastAPI()

# ---------- CORS setup ----------
origins = [
    "https://safloetsystems.xyz",
    "https://test.safloetsystems.xyz"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,   # required for sending cookies
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---------- Session setup ----------
app.add_middleware(
    SessionMiddleware,
    secret_key="supersecret",   # change for production
    session_cookie="session",
    https_only=True,
    same_site="none"            # allows cross-site cookies
)

# ---------- Discord OAuth ----------
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID") or "1414629698495053904"
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET") or "qCBWaQvMPC9lzdX3HVISwsNwcfunCY1e"
REDIRECT_URI = os.getenv("REDIRECT_URI") or "https://auth.safloetsystems.xyz/callback"
DISCORD_API = "https://discord.com/api"

# ---------- Home (for testing) ----------
@app.get("/")
async def home(request: Request):
    user = request.session.get("user")
    if user:
        return HTMLResponse(f"""
            <h1>Logged in as {user['username']}</h1>
            <img src="{user['avatar_url']}" width="100">
            <br><a href="/logout">Logout</a>
        """)
    return HTMLResponse('<a href="/login">Login with Discord</a>')

# ---------- Login endpoint ----------
@app.get("/login")
async def login(next: str = "https://safloetsystems.xyz"):
    discord_redirect = (
        f"{DISCORD_API}/oauth2/authorize?client_id={CLIENT_ID}"
        f"&redirect_uri={quote(REDIRECT_URI)}&response_type=code&scope=identify"
        f"&state={quote(next)}"
    )
    return RedirectResponse(discord_redirect)

# ---------- Callback endpoint ----------
@app.get("/callback")
async def callback(request: Request, code: str, state: str = ""):
    next_url = unquote(state) if state else "https://safloetsystems.xyz"
    async with httpx.AsyncClient() as client:
        # Exchange code for token
        data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_resp = await client.post(f"{DISCORD_API}/oauth2/token", data=data, headers=headers)
        token_resp.raise_for_status()
        token = token_resp.json().get("access_token")

        # Get user info
        user_resp = await client.get(f"{DISCORD_API}/users/@me", headers={"Authorization": f"Bearer {token}"})
        user_resp.raise_for_status()
        user = user_resp.json()

        avatar_url = f"https://cdn.discordapp.com/avatars/{user['id']}/{user['avatar']}.png"
        request.session["user"] = {
            "id": user["id"],
            "username": user["username"],
            "avatar_url": avatar_url
        }

    return RedirectResponse(next_url)

# ---------- Logout endpoint ----------
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return JSONResponse({"success": True})


# ---------- Get current user ----------
@app.get("/me")
async def me(request: Request):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"logged_in": False})
    return JSONResponse({"logged_in": True, "user": user})
