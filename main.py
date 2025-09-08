from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import stripe
from urllib.parse import quote, unquote
import firebase_admin

from firebase_admin import credentials, firestore
from datetime import datetime

app = FastAPI()

# ---------- Firebase setup ----------
try:
    # Initialize Firebase
    if not firebase_admin._apps:
        cred = credentials.Certificate("path/to/your/serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Firebase initialization error: {e}")

# ---------- Stripe setup ----------
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "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")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_6XceXrySIRsPEGXlTzf0TCuezE3OS2QV")

# ---------- Products configuration ----------
PRODUCTS = {
    "prod_1": {
        "id": "prod_1",
        "name": "Basic Package",
        "description": "Our basic package with essential features",
        "price": 999,  # $9.99
        "currency": "usd"
    },
    "prod_2": {
        "id": "prod_2",
        "name": "Premium Package",
        "description": "Our premium package with all features",
        "price": 2499,  # $24.99
        "currency": "usd"
    },
    "prod_3": {
        "id": "prod_3",
        "name": "Enterprise Package",
        "description": "Our enterprise solution for businesses",
        "price": 9999,  # $99.99
        "currency": "usd"
    }
}

# ---------- CORS setup ----------
origins = [
    "https://safloetsystems.xyz",
    "https://test.safloetsystems.xyz"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# ---------- Session setup ----------
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "supersecret"),
    session_cookie="session",
    https_only=True,
    same_site="none"
)

# ---------- Discord OAuth ----------
CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1414629698495053904")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "qCBWaQvMPC9lzdX3HVISwsNwcfunCY1e")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://auth.safloetsystems.xyz/callback")
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

# ---------- Stripe Checkout endpoint ----------
@app.post("/create-checkout-session")
async def create_checkout_session(request: Request, product_id: str):
    # Check if user is authenticated
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Validate product
    product = PRODUCTS.get(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    try:
        # Create Stripe checkout session
                # ...existing code...
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': product['currency'],
                    'product_data': {
                        'name': product['name'],
                        'description': product['description'],
                    },
                    'unit_amount': product['price'],
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=str(request.url_for('payment_success', _external=True)) +
                f"?session_id={{CHECKOUT_SESSION_ID}}&user_id={user['id']}&product_id={product_id}",
            cancel_url=str(request.url_for('payment_cancel', _external=True)),
            client_reference_id=user['id'],
            metadata={
                "user_id": user['id'],
                "product_id": product_id
            }
        )
        # ...existing code...
        
        return JSONResponse({"id": checkout_session.id})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------- Payment Success endpoint ----------
@app.get("/payment-success")
async def payment_success(request: Request, session_id: str, user_id: str, product_id: str):
    try:
        # Verify the session was successful
        session = stripe.checkout.Session.retrieve(session_id)
        
        if session.payment_status == 'paid':
            # Save to Firebase with count-based structure
            user_ref = db.collection("users").document(user_id)
            
            # Get current user data
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                purchases = user_data.get("purchases", {})
                
                # Update purchase count for this product
                current_count = purchases.get(product_id, 0)
                purchases[product_id] = current_count + 1
            else:
                # First purchase for this user
                purchases = {product_id: 1}
            
            # Also store individual purchase history in a subcollection
            purchase_data = {
                "product_id": product_id,
                "session_id": session_id,
                "amount_total": session.amount_total,
                "currency": session.currency,
                "payment_status": session.payment_status,
                "purchase_date": datetime.now(),
                "product_name": PRODUCTS[product_id]["name"]
            }
            
            # Update user document with purchase counts
            user_ref.set({"purchases": purchases}, merge=True)
            
            # Add to purchase history subcollection
            user_ref.collection("purchase_history").document(session_id).set(purchase_data)
            
            return RedirectResponse(f"https://safloetsystems.xyz/payment-success?session_id={session_id}")
        else:
            return RedirectResponse("https://safloetsystems.xyz/payment-failed")
    except Exception as e:
        print(f"Error processing successful payment: {e}")
        return RedirectResponse("https://safloetsystems.xyz/payment-error")

# ---------- Payment Cancel endpoint ----------
@app.get("/payment-cancel")
async def payment_cancel():
    return RedirectResponse("https://safloetsystems.xyz/payment-canceled")

# ---------- Stripe Webhook endpoint ----------
@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid payload")
    
    
    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Fulfill the purchase
        user_id = session['metadata']['user_id']
        product_id = session['metadata']['product_id']
        
        # Save to Firebase with count-based structure
        user_ref = db.collection("users").document(user_id)
        
        # Get current user data
        user_doc = user_ref.get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            purchases = user_data.get("purchases", {})
            
            # Update purchase count for this product
            current_count = purchases.get(product_id, 0)
            purchases[product_id] = current_count + 1
        else:
            # First purchase for this user
            purchases = {product_id: 1}
        
        # Also store individual purchase history
        purchase_data = {
            "product_id": product_id,
            "session_id": session['id'],
            "amount_total": session['amount_total'],
            "currency": session['currency'],
            "payment_status": session['payment_status'],
            "purchase_date": datetime.now(),
            "product_name": PRODUCTS[product_id]["name"]
        }
        
        # Update user document with purchase counts
        user_ref.set({"purchases": purchases}, merge=True)
        
        # Add to purchase history subcollection
        user_ref.collection("purchase_history").document(session['id']).set(purchase_data)
    
    return JSONResponse({"status": "success"})

# ---------- Check if user has product ----------
@app.get("/user/has-product/{product_id}")
async def user_has_product(request: Request, product_id: str):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        user_ref = db.collection("users").document(user['id'])
        user_doc = user_ref.get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            purchases = user_data.get("purchases", {})
            has_product = purchases.get(product_id, 0) > 0
            count = purchases.get(product_id, 0)
            
            return JSONResponse({
                "has_product": has_product,
                "purchase_count": count
            })
        else:
            return JSONResponse({
                "has_product": False,
                "purchase_count": 0
            })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------- Get all user purchases ----------
@app.get("/user/purchases")
async def get_user_purchases(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        user_ref = db.collection("users").document(user['id'])
        user_doc = user_ref.get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            purchases = user_data.get("purchases", {})
            
            # Convert to a more readable format with product names
            formatted_purchases = {}
            for product_id, count in purchases.items():
                product_info = PRODUCTS.get(product_id, {"name": f"Unknown Product ({product_id})"})
                formatted_purchases[product_id] = {
                    "count": count,
                    "name": product_info["name"]
                }
            
            return JSONResponse({"purchases": formatted_purchases})
        else:
            return JSONResponse({"purchases": {}})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))