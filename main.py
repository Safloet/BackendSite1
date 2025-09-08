from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
import os
from urllib.parse import quote

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="supersecret")  # change this to something strong

CLIENT_ID = "1414629698495053904"
CLIENT_SECRET = "qCBWaQvMPC9lzdX3HVISwsNwcfunCY1e"
REDIRECT_URI = "https://auth.safloetsystems.xyz/callback"
DISCORD_API = "https://discord.com/api"


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

# Login endpoint with optional 'next' URL
@app.get("/login")
async def login(next: str = "https://safloetsystems.xyz"):
    # Redirect to Discord OAuth
    discord_redirect = (
        f"{DISCORD_API}/oauth2/authorize?client_id={CLIENT_ID}"
        f"&redirect_uri={quote(REDIRECT_URI)}&response_type=code&scope=identify"
        f"&state={quote(next)}"
    )
    return RedirectResponse(discord_redirect)

# Callback endpoint from Discord
@app.get("/callback")
async def callback(request: Request, code: str, state: str = "https://safloetsystems.xyz"):
    async with httpx.AsyncClient() as client:
        data = {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        token_resp = await client.post(f"{DISCORD_API}/oauth2/token", data=data, headers=headers)
        token = token_resp.json().get("access_token")

        user_resp = await client.get(f"{DISCORD_API}/users/@me", headers={"Authorization": f"Bearer {token}"})
        user = user_resp.json()

        avatar_url = f"https://cdn.discordapp.com/avatars/{user['id']}/{user['avatar']}.png"
        request.session["user"] = {
            "id": user["id"],
            "username": user["username"],
            "avatar_url": avatar_url
        }

    # Redirect back to 'next' URL (defaults to main site)
    return RedirectResponse(state or "https://safloetsystems.xyz")

# Logout endpoint
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("https://safloetsystems.xyz")

# API endpoint for frontend to check login status
@app.get("/me")
async def me(request: Request):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"logged_in": False})
    return JSONResponse({"logged_in": True, "user": user})