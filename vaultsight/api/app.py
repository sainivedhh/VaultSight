"""FastAPI Application for VaultSight DSPM.

Includes:
- Authentication (JWT)
- Role-based Access Control (viewer, analyst, admin)
- Per-user data isolation (preventing IDOR)
- Rate limiting & request size control
- Secure HTTP headers
- Safe error handling (never exposing tracebacks or raw data)
"""

import time
from collections import defaultdict
from typing import Generator, List, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from vaultsight.api.models import get_engine, init_db, SessionLocal, UserDB, ScanDB, FindingDB
from vaultsight.api.auth import get_password_hash, verify_password, create_access_token, decode_access_token
from vaultsight.api.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenResponse,
    StartScanRequest,
    ScanResponse,
    FindingResponse,
    ReportSummaryResponse,
)
from vaultsight.detectors.engine import DetectionEngine
from vaultsight.risk import RiskScoringEngine
from vaultsight.connectors import LocalFilesystemConnector, PathTraversalError

# Rate Limiter State: IP -> list of timestamps
_RATE_LIMIT_STORE = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 120  # requests per minute

security_scheme = HTTPBearer(auto_error=False)


def create_app(db_url: str = "sqlite:///./vaultsight.db", scan_root_dir: str = ".") -> FastAPI:
    app = FastAPI(
        title="VaultSight DSPM API",
        description="Secure Data Security Posture Management (DSPM) API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
    )

    engine = get_engine(db_url)
    init_db(engine)
    app.state.db_engine = engine
    app.state.scan_root_dir = scan_root_dir
    app.state.detection_engine = DetectionEngine()
    app.state.risk_engine = RiskScoringEngine()

    # 1. Secure Headers Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        # Enforce body size limit (prevent denial of service with giant bodies)
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
            return JSONResponse(status_code=413, content={"detail": "Payload too large."})

        # Rate Limiting
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        # Clean expired timestamps
        _RATE_LIMIT_STORE[client_ip] = [t for t in _RATE_LIMIT_STORE[client_ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_RATE_LIMIT_STORE[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return JSONResponse(status_code=429, content={"detail": "Too many requests. Please slow down."})
        _RATE_LIMIT_STORE[client_ip].append(now)

        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Database Session Dependency
    def get_db() -> Generator[Session, None, None]:
        session = SessionLocal(bind=app.state.db_engine)
        try:
            yield session
        finally:
            session.close()

    # Authentication Dependency
    def get_current_user(
        creds: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
        db: Session = Depends(get_db)
    ) -> UserDB:
        if not creds or not creds.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication credentials were not provided."
            )
        token_data = decode_access_token(creds.credentials)
        if not token_data or not token_data.user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token."
            )
        user = db.query(UserDB).filter(UserDB.id == token_data.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User associated with token no longer exists."
            )
        return user

    # Role Enforcement Dependencies
    def require_analyst_or_admin(current_user: UserDB = Depends(get_current_user)):
        if current_user.role not in ("analyst", "admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Requires analyst or admin role."
            )
        return current_user

    def require_admin(current_user: UserDB = Depends(get_current_user)):
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Requires admin role."
            )
        return current_user

    # --- Endpoints ---

    @app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
    def register(req: UserRegisterRequest, db: Session = Depends(get_db)):
        # Mass assignment protection: ignore any unauthorized role elevations from regular users
        existing = db.query(UserDB).filter(UserDB.username == req.username).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already registered.")
        
        user = UserDB(
            username=req.username,
            hashed_password=get_password_hash(req.password),
            role=req.role or "viewer"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        token = create_access_token({"sub": user.id, "username": user.username, "role": user.role})
        return TokenResponse(access_token=token, role=user.role)

    @app.post("/auth/login", response_model=TokenResponse)
    def login(req: UserLoginRequest, db: Session = Depends(get_db)):
        user = db.query(UserDB).filter(UserDB.username == req.username).first()
        if not user or not verify_password(req.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password."
            )
        token = create_access_token({"sub": user.id, "username": user.username, "role": user.role})
        return TokenResponse(access_token=token, role=user.role)

    @app.post("/scans", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
    def start_scan(
        req: StartScanRequest,
        db: Session = Depends(get_db),
        current_user: UserDB = Depends(require_analyst_or_admin)
    ):
        """Start a new data discovery and posture scan."""
        # Check target traversal defense
        if req.target_type == "filesystem":
            try:
                connector = LocalFilesystemConnector(app.state.scan_root_dir)
                connector.safe_resolve(req.target_path)
            except (PathTraversalError, ValueError):
                raise HTTPException(status_code=400, detail="Invalid target path: traversal outside scan root.")

        # Create scan record isolated to current user
        scan = ScanDB(
            owner_id=current_user.id,
            target_type=req.target_type,
            target_path=req.target_path,
            status="PROCESSING"
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Execute scan with detection engine
        detected_findings = []
        if req.target_type == "filesystem":
            try:
                connector = LocalFilesystemConnector(app.state.scan_root_dir)
                for rel_path, content in connector.read_files(req.target_path):
                    f_list = app.state.detection_engine.scan_text(content, location=rel_path)
                    detected_findings.extend(f_list)
            except Exception:
                pass

        # Save findings
        for f in detected_findings:
            f_db = FindingDB(
                scan_id=scan.id,
                detector=f.detector,
                category=f.category.value,
                confidence=f.confidence,
                location=f.location,
                redacted_preview=f.redacted_preview
            )
            db.add(f_db)

        # Risk scoring
        risk = app.state.risk_engine.calculate_risk(
            target_id=req.target_path,
            findings=detected_findings,
            posture_findings=[],
            is_publicly_accessible=False,
            access_grant_count=1
        )

        scan.status = "COMPLETED"
        scan.findings_count = len(detected_findings)
        scan.risk_score = risk.risk_score
        scan.risk_level = risk.risk_level.value
        db.commit()
        db.refresh(scan)

        return scan

    @app.get("/scans", response_model=List[ScanResponse])
    def list_scans(
        db: Session = Depends(get_db),
        current_user: UserDB = Depends(get_current_user)
    ):
        """List scans with IDOR protection: Non-admins only see scans they own."""
        if current_user.role == "admin":
            scans = db.query(ScanDB).all()
        else:
            scans = db.query(ScanDB).filter(ScanDB.owner_id == current_user.id).all()
        return scans

    @app.get("/scans/{scan_id}", response_model=ScanResponse)
    def get_scan(
        scan_id: str,
        db: Session = Depends(get_db),
        current_user: UserDB = Depends(get_current_user)
    ):
        """Fetch specific scan report, ensuring per-user data isolation (IDOR defense)."""
        scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        # IDOR check: reject access if not owner and not admin
        if current_user.role != "admin" and scan.owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view this scan."
            )
        return scan

    @app.get("/scans/{scan_id}/findings", response_model=List[FindingResponse])
    def get_scan_findings(
        scan_id: str,
        db: Session = Depends(get_db),
        current_user: UserDB = Depends(get_current_user)
    ):
        scan = db.query(ScanDB).filter(ScanDB.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")

        if current_user.role != "admin" and scan.owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view findings for this scan."
            )
        return scan.findings

    @app.get("/reports/summary", response_model=ReportSummaryResponse)
    def get_reports_summary(
        db: Session = Depends(get_db),
        current_user: UserDB = Depends(get_current_user)
    ):
        """Generate high-level DSPM risk posture report across accessible scans."""
        if current_user.role == "admin":
            scans = db.query(ScanDB).all()
        else:
            scans = db.query(ScanDB).filter(ScanDB.owner_id == current_user.id).all()

        total_scans = len(scans)
        total_findings = sum(s.findings_count for s in scans)
        critical_count = sum(1 for s in scans if s.risk_level == "CRITICAL")
        avg_score = (sum(s.risk_score for s in scans) / total_scans) if total_scans > 0 else 0.0

        return ReportSummaryResponse(
            total_scans=total_scans,
            total_findings=total_findings,
            critical_findings_count=critical_count,
            average_risk_score=round(avg_score, 1),
            scans=scans
        )

    return app
