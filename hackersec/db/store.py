import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column, String, Integer, Text, DateTime,
    create_engine, ForeignKey
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session

DATABASE_URL = "sqlite:///./hackersec.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class Job(Base):
    __tablename__ = "jobs"
    id = Column(String, primary_key=True)
    status = Column(String, nullable=False, default="pending")  # pending|running|complete|failed
    target = Column(Text)
    target_type = Column(String)  # "file" | "git_url"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    error = Column(Text, nullable=True)
    finding_count = Column(Integer, default=0)


class FindingRecord(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("jobs.id"))
    file_path = Column(Text)
    line_start = Column(Integer)
    line_end = Column(Integer)
    rule_id = Column(String)
    tool = Column(String)
    severity = Column(String)
    message = Column(Text)
    cwe_ids = Column(Text, default="[]")     # JSON array string
    owasp_category = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)
    cpg_context = Column(Text, nullable=True)   # JSON
    rag_docs = Column(Text, nullable=True)      # JSON
    llm_analysis = Column(Text, nullable=True)  # JSON
    fusion_verdict = Column(Text, nullable=True)
    patch = Column(Text, nullable=True)


def init_db():
    Base.metadata.create_all(bind=engine)


def create_job(job_id: str, target: str, target_type: str) -> None:
    with SessionLocal() as db:
        job = Job(id=job_id, target=target, target_type=target_type, status="pending")
        db.add(job)
        db.commit()


def update_job(job_id: str, status: str, error: Optional[str] = None, finding_count: int = 0) -> None:
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job:
            job.status = status
            job.updated_at = datetime.utcnow()
            if error:
                job.error = error
            if finding_count:
                job.finding_count = finding_count
            db.commit()


def get_job(job_id: str) -> Optional[dict]:
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if not job:
            return None
        return {
            "id": job.id,
            "status": job.status,
            "target": job.target,
            "target_type": job.target_type,
            "created_at": str(job.created_at),
            "error": job.error,
            "finding_count": job.finding_count,
        }


def save_findings(job_id: str, findings: list) -> None:
    with SessionLocal() as db:
        for f in findings:
            record = FindingRecord(
                id=str(uuid.uuid4()),
                job_id=job_id,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                rule_id=f.rule_id,
                tool=f.tool,
                severity=f.severity,
                message=f.message,
                cwe_ids=json.dumps(f.cwe_ids),
                owasp_category=f.owasp_category,
                code_snippet=f.code_snippet,
                cpg_context=json.dumps(f.cpg_context) if f.cpg_context else None,
            )
            db.add(record)
        db.commit()


def get_findings(job_id: str) -> list[dict]:
    with SessionLocal() as db:
        from sqlalchemy import select
        stmt = select(FindingRecord).where(FindingRecord.job_id == job_id)
        records = db.execute(stmt).scalars().all()
        return [
            {
                "id": r.id,
                "file_path": r.file_path,
                "line_start": r.line_start,
                "severity": r.severity,
                "rule_id": r.rule_id,
                "tool": r.tool,
                "message": r.message,
                "cwe_ids": json.loads(r.cwe_ids or "[]"),
                "owasp_category": r.owasp_category,
                "code_snippet": r.code_snippet,
                "cpg_context": json.loads(r.cpg_context) if r.cpg_context else None,
                "fusion_verdict": r.fusion_verdict,
            }
            for r in records
        ]
