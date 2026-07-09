from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import uuid
from typing import Optional, List
from processor import process_netflow_data
from metrics import netflow_active_uploads
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response
app = FastAPI(title="NetFlow Threat Detection System API")

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify the actual frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for the latest processed results
# We store stats, alerts, and charts
db = {
    "stats": None,
    "alerts": [],
    "charts": None
}

UPLOAD_DIR = "/tmp/netflow_uploads" if os.name != 'nt' else "C:\\Temp\\netflow_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Accepts a NetFlow CSV file, runs processing, and saves the results in-memory.
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")
    
    # Check file size (200MB limit)
    MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB in bytes
    file.file.seek(0, 2)  # Seek to end
    file_size = file.file.tell()
    file.file.seek(0)  # Seek back to beginning
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail=f"File size exceeds 200MB limit. Your file is {file_size / (1024 * 1024):.2f}MB.")
    
    file_path = os.path.join(UPLOAD_DIR, f"temp_{uuid.uuid4().hex}_{file.filename}")
    
    netflow_active_uploads.inc()
    try:
        # Save uploaded file to disk temporarily for Polars ingestion
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Process the data
        stats, alerts, charts = process_netflow_data(file_path)
        
        # Store in-memory
        db["stats"] = stats
        db["alerts"] = alerts
        db["charts"] = charts
        
        return {
            "status": "success",
            "message": "File processed successfully",
            "processing_time_sec": stats["processing_time_sec"],
            "total_flows": stats["total_flows"],
            "threats_detected": stats["threats_detected"]
        }
        
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")
    finally:
        netflow_active_uploads.dec()
        # Clean up temporary file
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass

@app.get("/alerts")
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity: high, medium, low"),
    protocol: Optional[str] = Query(None, description="Filter by protocol: TCP, UDP, ICMP, etc.")
):
    """
    Returns the list of arbitrated and deduplicated alerts.
    Supports basic filtering via query parameters.
    """
    alerts = db["alerts"]
    if not alerts:
        return []
    
    filtered_alerts = alerts
    
    if severity:
        filtered_alerts = [a for a in filtered_alerts if a["severity"].upper() == severity.upper()]

    if protocol:
        filtered_alerts = [a for a in filtered_alerts if a.get("protocol", "").upper() == protocol.upper()]
        
    return filtered_alerts

@app.get("/stats")
async def get_stats():
    """
    Returns the summary statistics and charts data.
    """
    if db["stats"] is None:
        return {
            "stats": {
                "total_flows": 0,
                "threats_detected": 0,
                "top_attacker_ip": "N/A",
                "top_attacker_count": 0,
                "protocol_distribution": {},
                "processing_time_sec": 0
            },
            "charts": {
                "histogram": [],
                "threats_over_time": []
            }
        }
        
    return {
        "stats": db["stats"],
        "charts": db["charts"]
    }

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)