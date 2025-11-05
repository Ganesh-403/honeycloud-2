# 🍯 HoneyCloud-X: Smart Scalable Honeypot Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3-cyan.svg)](https://react.dev)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 Project Overview

**HoneyCloud-X** is a cutting-edge cloud-native honeypot platform designed for real-time cyber threat detection and analysis. Built as a final-year Computer Engineering project, it combines deception technology with AI/ML-powered threat intelligence.

### Key Features

✅ **Multi-Protocol Honeypots**: SSH, FTP, HTTP simulation  
✅ **AI Threat Detection**: Isolation Forest + XGBoost classification  
✅ **Real-Time Dashboard**: Live event streaming with SSE  
✅ **Smart Alerts**: Email + Discord webhooks  
✅ **Automated Reports**: PDF & CSV generation  
✅ **Cloud-Ready**: Docker containerized deployment  
✅ **Scalable Architecture**: PostgreSQL + SQLAlchemy ORM  

---

## 🏗️ Architecture

┌─────────────┐ ┌──────────────┐ ┌─────────────┐
│ Attackers │─────▶│ Honeypots │─────▶│ ML Engine │
│ │ │ SSH/FTP/HTTP │ │ IF + XGBoost│
└─────────────┘ └──────────────┘ └─────────────┘
│ │
▼ ▼
┌──────────────┐ ┌─────────────┐
│ PostgreSQL │◀────▶│ FastAPI │
│ Database │ │ Backend │
└──────────────┘ └─────────────┘
│
▼
┌─────────────┐
│ React │
│ Dashboard │
└─────────────┘


---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for local development)
- Node.js 20+ (for local development)

### 🐳 Docker Deployment (Recommended)

