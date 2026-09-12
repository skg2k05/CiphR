import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Table, Text, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.database import Base

# Many-to-many link table for samples and campaigns
sample_campaign_links = Table(
    'sample_campaign_links',
    Base.metadata,
    Column('sample_id', String, ForeignKey('samples.id', ondelete='CASCADE'), primary_key=True),
    Column('campaign_id', String, ForeignKey('campaigns.id', ondelete='CASCADE'), primary_key=True),
    Column('relationship', String),
    Column('confidence', Float),
    Column('reason', Text),
    Column('signals', JSON)
)

class Sample(Base):
    __tablename__ = 'samples'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    sha256 = Column(String, unique=True, index=True, nullable=False)
    size = Column(Integer)
    source = Column(String)
    submitted_by = Column(String)
    status = Column(String, default='QUEUED')  # QUEUED, ANALYZING, COMPLETED, FAILED
    storage_path = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    analysis = relationship("Analysis", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="sample", cascade="all, delete-orphan")
    campaigns = relationship("Campaign", secondary=sample_campaign_links, back_populates="samples")

    @property
    def source_type(self) -> str:
        if self.source and self.source.startswith("url|"):
            return "url"
        return "upload"

    @property
    def source_url(self) -> str | None:
        if self.source and self.source.startswith("url|"):
            return self.source[4:]
        return None

class Analysis(Base):
    __tablename__ = 'analyses'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sample_id = Column(String, ForeignKey('samples.id', ondelete='CASCADE'), unique=True)
    status = Column(String, default='PENDING')
    package_name = Column(String, index=True)
    app_name = Column(String)
    version_name = Column(String)
    version_code = Column(String)
    min_sdk = Column(String)
    target_sdk = Column(String)
    tlsh = Column(String, index=True)
    certificate_fingerprint = Column(String, index=True)
    risk_score = Column(Integer)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    error_message = Column(Text)
    threat_narrative = Column(Text)
    activities = Column(JSON)
    services = Column(JSON)
    receivers = Column(JSON)
    risk_factors = Column(JSON)
    dex_data = Column(JSON)

    sample = relationship("Sample", back_populates="analysis")

class Finding(Base):
    __tablename__ = 'findings'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sample_id = Column(String, ForeignKey('samples.id', ondelete='CASCADE'))
    title = Column(String, nullable=False)
    description = Column(Text)
    severity = Column(String)  # LOW, MEDIUM, HIGH, CRITICAL
    category = Column(String)
    evidence = Column(Text)
    mitre_technique_id = Column(String)
    confidence = Column(Float)
    
    sample = relationship("Sample", back_populates="findings")

class Campaign(Base):
    __tablename__ = 'campaigns'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, unique=True)
    description = Column(Text)
    risk_score = Column(Integer)
    severity = Column(String) # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default='ACTIVE')
    intelligence_summary = Column(JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    samples = relationship("Sample", secondary=sample_campaign_links, back_populates="campaigns")

class APIKey(Base):
    __tablename__ = 'api_keys'
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key_hash = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_used_at = Column(DateTime, nullable=True)

