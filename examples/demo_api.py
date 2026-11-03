"""Demo target API. v1 is clean; v2 'accidentally' leaks PII.
Run:  uvicorn examples.demo_api:app --port 8000
"""

from fastapi import FastAPI

app = FastAPI(title="Demo HR API")

# Fake data only. The Aadhaar number has a valid Verhoeff check digit.
USER_V1 = {"id": 1, "name": "Asha Rao", "country": "IN"}
USER_V2 = {
    **USER_V1,
    "email": "asha.rao@example.com",
    "phone": "+91 98765 43210",  # NOT documented in the v2 spec
    "aadhaar_number": "2345 6789 0124",
    "tax_id": "ABCPE1234F",  # PAN under a non-obvious field name
    "bank": {"ifsc": "SBIN0001234", "upi_id": "asha.rao@okaxis"},
}


@app.get("/v1/users/{user_id}")
def get_user_v1(user_id: int):
    return {**USER_V1, "id": user_id}


@app.get("/v1/orders")
def list_orders_v1():
    return [{"id": 10, "total": 499.0}, {"id": 11, "total": 120.5}]


@app.get("/v2/users/{user_id}")
def get_user_v2(user_id: int):
    return {**USER_V2, "id": user_id}


@app.get("/v2/orders")
def list_orders_v2():
    return [
        {"id": 10, "total": 499.0, "customer_email": "asha.rao@example.com"},
        {"id": 11, "total": 120.5, "customer_email": "ravi.k@example.com"},
    ]


@app.get("/v2/health")
def health_v2():
    return {"status": "ok", "build": "2026.11.03"}


@app.post("/v2/users")
def create_user_v2(body: dict):
    return {"created": True}
