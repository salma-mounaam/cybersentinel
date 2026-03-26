from fastapi import FastAPI

app = FastAPI(title="CyberSentinel FastAPI Gateway")

@app.get("/")
def read_root():
    return {"message": "CyberSentinel API is running"}