from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

def now(): return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String)
    baseline_spend: Mapped[float] = mapped_column(Float, default=100.0)

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    device_type: Mapped[str | None] = mapped_column(String, nullable=True, default="IoT Terminal")
    expected_latitude: Mapped[float] = mapped_column(Float)
    expected_longitude: Mapped[float] = mapped_column(Float)
    latitude: Mapped[float] = mapped_column(Float)
    longitude: Mapped[float] = mapped_column(Float)
    vibration: Mapped[float] = mapped_column(Float, default=0)
    tamper_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    online: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    __table_args__ = (Index("ix_devices_online", "online"), Index("ix_devices_last_seen", "last_seen"))

class WebVisitor(Base):
    __tablename__ = "web_visitors"
    visitor_id: Mapped[str] = mapped_column(String, primary_key=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    country: Mapped[str] = mapped_column(String, default="Unknown")
    region: Mapped[str] = mapped_column(String, default="Unknown")
    city: Mapped[str] = mapped_column(String, default="Unknown")
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    device_type: Mapped[str] = mapped_column(String, default="Unknown")
    device_name: Mapped[str] = mapped_column(String, default="Unknown")
    browser: Mapped[str] = mapped_column(String, default="Unknown")
    browser_version: Mapped[str] = mapped_column(String, default="Unknown")
    operating_system: Mapped[str] = mapped_column(String, default="Unknown")
    user_agent: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    online: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (Index("ix_web_visitors_online", "online"), Index("ix_web_visitors_last_seen", "last_seen"))

class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    amount: Mapped[float] = mapped_column(Float)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    merchant: Mapped[str] = mapped_column(String)
    ip_address: Mapped[str] = mapped_column(String)
    device_id: Mapped[str] = mapped_column(String)
    latitude: Mapped[float] = mapped_column(Float)
    longitude: Mapped[float] = mapped_column(Float)
    transaction_velocity: Mapped[float] = mapped_column(Float, default=1)
    status: Mapped[str] = mapped_column(String, default="ALLOW")
    __table_args__ = (Index("ix_transactions_timestamp", "timestamp"),)

class IoTReading(Base):
    __tablename__ = "iot_readings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    latitude: Mapped[float] = mapped_column(Float)
    longitude: Mapped[float] = mapped_column(Float)
    vibration: Mapped[float] = mapped_column(Float)
    tamper_detected: Mapped[bool] = mapped_column(Boolean)
    online: Mapped[bool] = mapped_column(Boolean, default=True)

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transaction_id: Mapped[str] = mapped_column(ForeignKey("transactions.id"), unique=True)
    fraud_probability: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float] = mapped_column(Float)
    behaviour_score: Mapped[float] = mapped_column(Float)
    ip_score: Mapped[float] = mapped_column(Float)
    device_score: Mapped[float] = mapped_column(Float)
    location_score: Mapped[float] = mapped_column(Float)
    iot_tamper_score: Mapped[float] = mapped_column(Float)
    final_risk_score: Mapped[float] = mapped_column(Float)
    decision: Mapped[str] = mapped_column(String)
    explanation: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    severity: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text)
    transaction_id: Mapped[str | None] = mapped_column(String, nullable=True)
    device_id: Mapped[str | None] = mapped_column(String, nullable=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (Index("ix_alerts_created_at", "created_at"),)

class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transaction_id: Mapped[str] = mapped_column(String)
    label: Mapped[str] = mapped_column(String)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
