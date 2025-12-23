# ShadowTwin AWS Deployment Guide

## Migration from Replit to AWS (EC2/ECS + RDS)

This document provides comprehensive guidance for migrating the ShadowTwin platform from Replit to a highly scalable AWS environment.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Database Migration (RDS)](#database-migration-rds)
4. [Option A: EC2 Deployment](#option-a-ec2-deployment)
5. [Option B: ECS Deployment](#option-b-ecs-deployment)
6. [Redis Setup (ElastiCache)](#redis-setup-elasticache)
7. [Environment Configuration](#environment-configuration)
8. [Load Balancer & SSL](#load-balancer--ssl)
9. [Auto-Scaling Configuration](#auto-scaling-configuration)
10. [Monitoring & Logging](#monitoring--logging)
11. [Security Best Practices](#security-best-practices)
12. [Backup & Disaster Recovery](#backup--disaster-recovery)
13. [Cost Estimation](#cost-estimation)

---

## Architecture Overview

### Recommended Production Architecture

```
                                    ┌─────────────────┐
                                    │   CloudFront    │
                                    │   (CDN/SSL)     │
                                    └────────┬────────┘
                                             │
                                    ┌────────▼────────┐
                                    │  Application    │
                                    │  Load Balancer  │
                                    └────────┬────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
           ┌────────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
           │   ECS Task 1    │      │   ECS Task 2    │      │   ECS Task N    │
           │  (ShadowTwin)   │      │  (ShadowTwin)   │      │  (ShadowTwin)   │
           └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
                    │                        │                        │
                    └────────────────────────┼────────────────────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
           ┌────────▼────────┐      ┌────────▼────────┐      ┌────────▼────────┐
           │  RDS PostgreSQL │      │   ElastiCache   │      │       S3        │
           │   (Primary)     │      │    (Redis)      │      │  (PDF Reports)  │
           └────────┬────────┘      └─────────────────┘      └─────────────────┘
                    │
           ┌────────▼────────┐
           │  RDS PostgreSQL │
           │   (Read Replica)│
           └─────────────────┘
```

### Components

| Component | AWS Service | Purpose |
|-----------|-------------|---------|
| Application | ECS Fargate / EC2 | Node.js application runtime |
| Database | RDS PostgreSQL | Primary data storage |
| Cache/Queue | ElastiCache Redis | BullMQ job queue |
| CDN | CloudFront | Static asset delivery, SSL |
| Load Balancer | ALB | Traffic distribution, health checks |
| Storage | S3 | PDF report storage |
| Secrets | Secrets Manager | Environment variables |
| Monitoring | CloudWatch | Logs, metrics, alarms |

---

## Prerequisites

### Required AWS Resources

1. **AWS Account** with appropriate IAM permissions
2. **VPC** with public and private subnets across 2+ availability zones
3. **Domain name** configured in Route 53 or external DNS
4. **SSL Certificate** in AWS Certificate Manager (ACM)

### Local Requirements

- AWS CLI v2 installed and configured
- Docker installed (for ECS deployment)
- Node.js 20+ (for build process)
- PostgreSQL client (for database migration)

### IAM Permissions Required

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "ecs:*",
        "ecr:*",
        "rds:*",
        "elasticache:*",
        "elasticloadbalancing:*",
        "s3:*",
        "secretsmanager:*",
        "cloudwatch:*",
        "logs:*",
        "iam:PassRole"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Database Migration (RDS)

### Step 1: Create RDS PostgreSQL Instance

```bash
# Create RDS instance via CLI
aws rds create-db-instance \
  --db-instance-identifier shadowtwin-prod \
  --db-instance-class db.t3.medium \
  --engine postgres \
  --engine-version 15 \
  --master-username shadowtwin_admin \
  --master-user-password "YOUR_SECURE_PASSWORD" \
  --allocated-storage 100 \
  --storage-type gp3 \
  --vpc-security-group-ids sg-xxxxxxxx \
  --db-subnet-group-name shadowtwin-db-subnet \
  --backup-retention-period 7 \
  --multi-az \
  --storage-encrypted \
  --deletion-protection
```

### RDS Configuration Recommendations

| Setting | Value | Rationale |
|---------|-------|-----------|
| Instance Class | db.t3.medium (start) | Scale to db.r6g.large for production |
| Storage | gp3, 100GB+ | Baseline 3000 IOPS, autoscaling enabled |
| Multi-AZ | Enabled | High availability |
| Encryption | Enabled (AES-256) | Data at rest security |
| Backup Retention | 7-35 days | Point-in-time recovery |
| Parameter Group | Custom | Optimize for workload |

### Step 2: Export Data from Replit Database

```bash
# On Replit, export database
pg_dump -h $PGHOST -U $PGUSER -d $PGDATABASE -F c -f shadowtwin_backup.dump

# Download the dump file from Replit
```

### Step 3: Import Data to RDS

```bash
# Restore to RDS
pg_restore -h your-rds-endpoint.rds.amazonaws.com \
  -U shadowtwin_admin \
  -d shadowtwin \
  -F c shadowtwin_backup.dump

# Or use psql for SQL dumps
psql -h your-rds-endpoint.rds.amazonaws.com \
  -U shadowtwin_admin \
  -d shadowtwin < shadowtwin_backup.sql
```

### Step 4: Create Read Replica (Optional, for scaling)

```bash
aws rds create-db-instance-read-replica \
  --db-instance-identifier shadowtwin-read-replica \
  --source-db-instance-identifier shadowtwin-prod \
  --db-instance-class db.t3.medium
```

---

## Option A: EC2 Deployment

### Step 1: Launch EC2 Instance

```bash
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxx \
  --subnet-id subnet-xxxxxxxx \
  --iam-instance-profile Name=ShadowTwinEC2Role \
  --user-data file://ec2-user-data.sh \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=shadowtwin-app}]'
```

### EC2 User Data Script (ec2-user-data.sh)

```bash
#!/bin/bash
set -e

# Update system
yum update -y

# Install Node.js 20
curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
yum install -y nodejs

# Install PM2 for process management
npm install -g pm2

# Install git
yum install -y git

# Create app directory
mkdir -p /opt/shadowtwin
cd /opt/shadowtwin

# Clone repository (or use CodeDeploy)
git clone https://github.com/your-org/shadowtwin.git .

# Install dependencies
npm ci --production

# Build the application
npm run build

# Configure PM2
pm2 start dist/index.cjs --name shadowtwin
pm2 save
pm2 startup

# Configure log rotation
pm2 install pm2-logrotate
```

### EC2 Instance Sizing Guide

| Workload | Instance Type | vCPU | Memory | Recommended For |
|----------|---------------|------|--------|-----------------|
| Development | t3.small | 2 | 2 GB | Testing |
| Small Production | t3.medium | 2 | 4 GB | < 100 users |
| Medium Production | t3.large | 2 | 8 GB | 100-500 users |
| Large Production | c6i.xlarge | 4 | 8 GB | 500+ users |
| ELITE Workloads | c6i.2xlarge | 8 | 16 GB | Heavy AI processing |

---

## Option B: ECS Deployment (Recommended)

### Step 1: Create ECR Repository

```bash
aws ecr create-repository \
  --repository-name shadowtwin \
  --image-scanning-configuration scanOnPush=true \
  --encryption-configuration encryptionType=AES256
```

### Step 2: Create Dockerfile

```dockerfile
# Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build

# Production image
FROM node:20-alpine AS production

WORKDIR /app

# Install production dependencies only
COPY package*.json ./
RUN npm ci --production

# Copy built application
COPY --from=builder /app/dist ./dist

# Security: Run as non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001
USER nodejs

EXPOSE 5000

ENV NODE_ENV=production

CMD ["node", "dist/index.cjs"]
```

### Step 3: Build and Push Docker Image

```bash
# Authenticate with ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Build image
docker build -t shadowtwin:latest .

# Tag and push
docker tag shadowtwin:latest YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shadowtwin:latest
docker push YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shadowtwin:latest
```

### Step 4: Create ECS Task Definition

```json
{
  "family": "shadowtwin",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT_ID:role/shadowtwinTaskRole",
  "containerDefinitions": [
    {
      "name": "shadowtwin",
      "image": "ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/shadowtwin:latest",
      "portMappings": [
        {
          "containerPort": 5000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "PORT", "value": "5000"}
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:shadowtwin/database"
        },
        {
          "name": "REDIS_URL",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:shadowtwin/redis"
        },
        {
          "name": "OPENAI_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:shadowtwin/openai"
        },
        {
          "name": "ADMIN_EMAIL",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:shadowtwin/admin-email"
        },
        {
          "name": "ADMIN_PASSWORD_HASH",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:shadowtwin/admin-password-hash"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/shadowtwin",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:5000/api/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### Step 5: Create ECS Service

```bash
aws ecs create-service \
  --cluster shadowtwin-cluster \
  --service-name shadowtwin-service \
  --task-definition shadowtwin:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=shadowtwin,containerPort=5000" \
  --deployment-configuration "maximumPercent=200,minimumHealthyPercent=100"
```

---

## Redis Setup (ElastiCache)

### Create ElastiCache Redis Cluster

```bash
aws elasticache create-cache-cluster \
  --cache-cluster-id shadowtwin-redis \
  --cache-node-type cache.t3.small \
  --engine redis \
  --engine-version 7.0 \
  --num-cache-nodes 1 \
  --cache-subnet-group-name shadowtwin-cache-subnet \
  --security-group-ids sg-xxxxxxxx
```

### For Production: Create Redis Replication Group (Cluster Mode)

```bash
aws elasticache create-replication-group \
  --replication-group-id shadowtwin-redis-cluster \
  --replication-group-description "ShadowTwin Redis Cluster" \
  --automatic-failover-enabled \
  --multi-az-enabled \
  --num-cache-clusters 2 \
  --cache-node-type cache.r6g.large \
  --engine redis \
  --engine-version 7.0 \
  --cache-subnet-group-name shadowtwin-cache-subnet \
  --security-group-ids sg-xxxxxxxx \
  --at-rest-encryption-enabled \
  --transit-encryption-enabled
```

---

## Environment Configuration

### AWS Secrets Manager Setup

```bash
# Create secrets
aws secretsmanager create-secret \
  --name shadowtwin/database \
  --secret-string "postgresql://user:password@rds-endpoint:5432/shadowtwin"

aws secretsmanager create-secret \
  --name shadowtwin/redis \
  --secret-string "redis://elasticache-endpoint:6379"

aws secretsmanager create-secret \
  --name shadowtwin/openai \
  --secret-string "sk-your-openai-key"

aws secretsmanager create-secret \
  --name shadowtwin/admin-email \
  --secret-string "admin@yourdomain.com"

aws secretsmanager create-secret \
  --name shadowtwin/admin-password-hash \
  --secret-string "$2b$12$your-bcrypt-hash"
```

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `REDIS_URL` | Redis connection string | `redis://host:6379` |
| `OPENAI_API_KEY` | OpenAI API key for AI features | `sk-...` |
| `ADMIN_EMAIL` | Admin panel email | `admin@domain.com` |
| `ADMIN_PASSWORD_HASH` | Bcrypt hash (12 rounds) | `$2b$12$...` |
| `SMTP_HOST` | Email server hostname | `smtp.sendgrid.net` |
| `SMTP_PORT` | SMTP port | `587` |
| `SMTP_USER` | SMTP username | `apikey` |
| `SMTP_PASS` | SMTP password | `SG.xxx` |
| `SMTP_FROM` | Sender email address | `noreply@domain.com` |

---

## Load Balancer & SSL

### Create Application Load Balancer

```bash
# Create ALB
aws elbv2 create-load-balancer \
  --name shadowtwin-alb \
  --subnets subnet-xxx subnet-yyy \
  --security-groups sg-xxx \
  --scheme internet-facing \
  --type application

# Create target group
aws elbv2 create-target-group \
  --name shadowtwin-tg \
  --protocol HTTP \
  --port 5000 \
  --vpc-id vpc-xxx \
  --target-type ip \
  --health-check-path /api/health \
  --health-check-interval-seconds 30

# Create HTTPS listener
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:... \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=arn:aws:acm:... \
  --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:...

# Create HTTP -> HTTPS redirect
aws elbv2 create-listener \
  --load-balancer-arn arn:aws:elasticloadbalancing:... \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'
```

---

## Auto-Scaling Configuration

### ECS Service Auto Scaling

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/shadowtwin-cluster/shadowtwin-service \
  --min-capacity 2 \
  --max-capacity 20

# CPU-based scaling policy
aws application-autoscaling put-scaling-policy \
  --policy-name shadowtwin-cpu-scaling \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/shadowtwin-cluster/shadowtwin-service \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    },
    "ScaleOutCooldown": 60,
    "ScaleInCooldown": 300
  }'

# Memory-based scaling policy
aws application-autoscaling put-scaling-policy \
  --policy-name shadowtwin-memory-scaling \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/shadowtwin-cluster/shadowtwin-service \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 75.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageMemoryUtilization"
    },
    "ScaleOutCooldown": 60,
    "ScaleInCooldown": 300
  }'
```

---

## Monitoring & Logging

### CloudWatch Dashboard

Create a CloudWatch dashboard with:

1. **ECS Metrics**: CPU/Memory utilization, task count
2. **RDS Metrics**: CPU, connections, read/write IOPS
3. **ALB Metrics**: Request count, latency, 4xx/5xx errors
4. **ElastiCache Metrics**: CPU, memory, cache hits/misses

### CloudWatch Alarms

```bash
# High CPU alarm
aws cloudwatch put-metric-alarm \
  --alarm-name shadowtwin-high-cpu \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --threshold 85 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT_ID:alerts

# Database connections alarm
aws cloudwatch put-metric-alarm \
  --alarm-name shadowtwin-db-connections \
  --metric-name DatabaseConnections \
  --namespace AWS/RDS \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT_ID:alerts
```

### Log Groups

```bash
# Create log groups
aws logs create-log-group --log-group-name /ecs/shadowtwin
aws logs put-retention-policy --log-group-name /ecs/shadowtwin --retention-in-days 30
```

---

## Security Best Practices

### Network Security

1. **VPC Design**: Place application in private subnets, only ALB in public
2. **Security Groups**: Restrict inbound to necessary ports only
3. **NACLs**: Additional layer for subnet-level filtering

### Security Group Rules

```bash
# ALB Security Group
aws ec2 create-security-group \
  --group-name shadowtwin-alb-sg \
  --description "ALB Security Group"

aws ec2 authorize-security-group-ingress \
  --group-id sg-alb \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id sg-alb \
  --protocol tcp --port 80 --cidr 0.0.0.0/0

# ECS Task Security Group
aws ec2 create-security-group \
  --group-name shadowtwin-ecs-sg \
  --description "ECS Task Security Group"

aws ec2 authorize-security-group-ingress \
  --group-id sg-ecs \
  --protocol tcp --port 5000 --source-group sg-alb

# RDS Security Group
aws ec2 create-security-group \
  --group-name shadowtwin-rds-sg \
  --description "RDS Security Group"

aws ec2 authorize-security-group-ingress \
  --group-id sg-rds \
  --protocol tcp --port 5432 --source-group sg-ecs
```

### Data Encryption

- **At Rest**: RDS encryption enabled, EBS encryption for EC2
- **In Transit**: SSL/TLS for all connections
- **Secrets**: AWS Secrets Manager with rotation

---

## Backup & Disaster Recovery

### RDS Automated Backups

```bash
aws rds modify-db-instance \
  --db-instance-identifier shadowtwin-prod \
  --backup-retention-period 35 \
  --preferred-backup-window "03:00-04:00"
```

### Manual Snapshots

```bash
# Create manual snapshot before major changes
aws rds create-db-snapshot \
  --db-instance-identifier shadowtwin-prod \
  --db-snapshot-identifier shadowtwin-pre-migration-$(date +%Y%m%d)
```

### Cross-Region Replication (DR)

```bash
aws rds create-db-instance-read-replica \
  --db-instance-identifier shadowtwin-dr-replica \
  --source-db-instance-identifier arn:aws:rds:us-east-1:ACCOUNT:db:shadowtwin-prod \
  --region us-west-2
```

---

## Cost Estimation

### Monthly Cost Breakdown (Estimated)

| Service | Configuration | Monthly Cost (USD) |
|---------|---------------|-------------------|
| ECS Fargate | 2 tasks, 1 vCPU, 2GB | $75 |
| RDS PostgreSQL | db.t3.medium, Multi-AZ | $150 |
| ElastiCache Redis | cache.t3.small | $25 |
| ALB | Standard usage | $30 |
| CloudFront | 100GB transfer | $15 |
| S3 | 50GB storage | $2 |
| Secrets Manager | 10 secrets | $5 |
| CloudWatch | Logs + metrics | $20 |
| **Total** | | **~$320/month** |

### Scaling Costs

- Additional ECS task: ~$35/month
- RDS db.r6g.large: ~$400/month
- ElastiCache r6g.large: ~$200/month

---

## Deployment Checklist

### Pre-Deployment

- [ ] VPC and subnets created
- [ ] Security groups configured
- [ ] RDS instance provisioned
- [ ] ElastiCache cluster created
- [ ] Secrets stored in Secrets Manager
- [ ] SSL certificate provisioned in ACM
- [ ] ECR repository created

### Deployment

- [ ] Docker image built and pushed
- [ ] ECS task definition created
- [ ] ECS service deployed
- [ ] ALB configured with HTTPS listener
- [ ] DNS records updated
- [ ] Health checks passing

### Post-Deployment

- [ ] CloudWatch alarms configured
- [ ] Auto-scaling policies enabled
- [ ] Backup verification
- [ ] Performance testing completed
- [ ] Security scan passed

---

## Support & Troubleshooting

### Common Issues

1. **Container fails to start**: Check CloudWatch logs, verify secrets are accessible
2. **Database connection refused**: Verify security group allows ECS -> RDS
3. **High latency**: Check RDS performance insights, consider read replicas
4. **Memory issues**: Increase task memory or add more tasks

### Useful Commands

```bash
# View ECS service events
aws ecs describe-services --cluster shadowtwin-cluster --services shadowtwin-service

# View running tasks
aws ecs list-tasks --cluster shadowtwin-cluster --service-name shadowtwin-service

# View task logs
aws logs get-log-events --log-group-name /ecs/shadowtwin --log-stream-name ecs/shadowtwin/xxx

# Force new deployment
aws ecs update-service --cluster shadowtwin-cluster --service shadowtwin-service --force-new-deployment
```

---

## CI/CD Pipeline Integration

### GitHub Actions Workflow

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to AWS ECS

on:
  push:
    branches: [main]
  workflow_dispatch:

env:
  AWS_REGION: us-east-1
  ECR_REPOSITORY: shadowtwin
  ECS_CLUSTER: shadowtwin-cluster
  ECS_SERVICE: shadowtwin-service
  TASK_DEFINITION: shadowtwin

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run check
      - run: npm test

  build-and-deploy:
    needs: test
    runs-on: ubuntu-latest
    environment: production
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2
      
      - name: Build, tag, and push image to Amazon ECR
        id: build-image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
          docker tag $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG $ECR_REGISTRY/$ECR_REPOSITORY:latest
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:latest
          echo "image=$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG" >> $GITHUB_OUTPUT
      
      - name: Download task definition
        run: |
          aws ecs describe-task-definition --task-definition $TASK_DEFINITION \
            --query taskDefinition > task-definition.json
      
      - name: Update task definition with new image
        id: task-def
        uses: aws-actions/amazon-ecs-render-task-definition@v1
        with:
          task-definition: task-definition.json
          container-name: shadowtwin
          image: ${{ steps.build-image.outputs.image }}
      
      - name: Deploy to Amazon ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: ${{ steps.task-def.outputs.task-definition }}
          service: ${{ env.ECS_SERVICE }}
          cluster: ${{ env.ECS_CLUSTER }}
          wait-for-service-stability: true
```

### Deployment Environments

| Environment | Branch | Auto-Deploy | Approval Required |
|-------------|--------|-------------|-------------------|
| Development | `develop` | Yes | No |
| Staging | `staging` | Yes | No |
| Production | `main` | Manual | Yes |

---

## Zero-Downtime Migration Plan

### Pre-Migration Preparation (1 Week Before)

1. **Infrastructure Setup**
   - Provision all AWS resources (VPC, RDS, ElastiCache, ECS cluster)
   - Configure security groups and networking
   - Set up monitoring and alerting

2. **Data Sync Test**
   - Export test data from Replit
   - Import to staging RDS
   - Verify data integrity

3. **Application Testing**
   - Deploy to staging environment
   - Run full test suite
   - Perform load testing

### Migration Day Runbook

```
T-2 hours:  Final backup of Replit database
T-1 hour:   Put application in maintenance mode
T-0:        Begin migration
            - Export latest database from Replit
            - Import to RDS
            - Verify data counts match
            - Update DNS TTL to 60 seconds
T+30 min:   Deploy application to ECS
            - Verify health checks passing
            - Test critical user flows
T+1 hour:   DNS cutover
            - Update DNS to point to ALB
            - Monitor for errors
T+2 hours:  Validation
            - Verify all functionality
            - Check logs for errors
            - Confirm metrics in CloudWatch
T+24 hours: Post-migration review
            - Restore DNS TTL
            - Document lessons learned
```

### Rollback Trigger Criteria

Initiate rollback if any of:
- Error rate exceeds 5% for 5 minutes
- P95 latency exceeds 3 seconds
- Critical functionality broken
- Database connection failures

---

## Health Check Strategy

### Application Health Endpoint

Add to your server code:

```typescript
app.get('/api/health', async (req, res) => {
  const checks = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.APP_VERSION || 'unknown',
    checks: {
      database: 'unknown',
      redis: 'unknown',
      memory: 'unknown'
    }
  };
  
  try {
    // Database check
    await db.execute(sql`SELECT 1`);
    checks.checks.database = 'healthy';
  } catch (e) {
    checks.checks.database = 'unhealthy';
    checks.status = 'degraded';
  }
  
  try {
    // Redis check (if configured)
    if (redisClient) {
      await redisClient.ping();
      checks.checks.redis = 'healthy';
    } else {
      checks.checks.redis = 'not_configured';
    }
  } catch (e) {
    checks.checks.redis = 'unhealthy';
    checks.status = 'degraded';
  }
  
  // Memory check
  const used = process.memoryUsage();
  const heapPercent = (used.heapUsed / used.heapTotal) * 100;
  checks.checks.memory = heapPercent < 90 ? 'healthy' : 'warning';
  
  const statusCode = checks.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(checks);
});
```

### ALB Health Check Configuration

```bash
aws elbv2 modify-target-group \
  --target-group-arn arn:aws:elasticloadbalancing:... \
  --health-check-protocol HTTP \
  --health-check-path /api/health \
  --health-check-interval-seconds 30 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3 \
  --matcher HttpCode=200
```

### ECS Task Health Check

```json
{
  "healthCheck": {
    "command": [
      "CMD-SHELL",
      "curl -f http://localhost:5000/api/health || exit 1"
    ],
    "interval": 30,
    "timeout": 5,
    "retries": 3,
    "startPeriod": 60
  }
}
```

---

## Secrets Rotation Strategy

### Automatic Rotation with AWS Secrets Manager

```bash
# Enable rotation for database credentials
aws secretsmanager rotate-secret \
  --secret-id shadowtwin/database \
  --rotation-lambda-arn arn:aws:lambda:us-east-1:ACCOUNT:function:SecretsManagerRDSRotation \
  --rotation-rules AutomaticallyAfterDays=30
```

### Manual Rotation Procedure

1. **Database Password Rotation**
   ```bash
   # 1. Generate new password
   NEW_PASSWORD=$(openssl rand -base64 32)
   
   # 2. Update RDS password
   aws rds modify-db-instance \
     --db-instance-identifier shadowtwin-prod \
     --master-user-password "$NEW_PASSWORD" \
     --apply-immediately
   
   # 3. Update secret
   aws secretsmanager update-secret \
     --secret-id shadowtwin/database \
     --secret-string "postgresql://user:$NEW_PASSWORD@endpoint:5432/db"
   
   # 4. Force ECS deployment to pick up new secret
   aws ecs update-service \
     --cluster shadowtwin-cluster \
     --service shadowtwin-service \
     --force-new-deployment
   ```

2. **API Key Rotation**
   ```bash
   # Update OpenAI API key
   aws secretsmanager update-secret \
     --secret-id shadowtwin/openai \
     --secret-string "sk-new-api-key"
   
   # Force deployment
   aws ecs update-service --cluster shadowtwin-cluster \
     --service shadowtwin-service --force-new-deployment
   ```

### Rotation Schedule

| Secret | Rotation Frequency | Method |
|--------|-------------------|--------|
| Database Password | 30 days | Automatic |
| Redis Password | 90 days | Manual |
| OpenAI API Key | On compromise | Manual |
| Admin Password | 90 days | Manual |

---

## Rollback Procedures

### ECS Service Rollback

```bash
# Option 1: Rollback to previous task definition
# Get previous task definition
PREVIOUS_TASK=$(aws ecs describe-services \
  --cluster shadowtwin-cluster \
  --services shadowtwin-service \
  --query 'services[0].deployments[1].taskDefinition' \
  --output text)

# Deploy previous version
aws ecs update-service \
  --cluster shadowtwin-cluster \
  --service shadowtwin-service \
  --task-definition $PREVIOUS_TASK \
  --force-new-deployment

# Option 2: Rollback to specific version
aws ecs update-service \
  --cluster shadowtwin-cluster \
  --service shadowtwin-service \
  --task-definition shadowtwin:42 \
  --force-new-deployment
```

### Database Rollback

```bash
# Restore from automated backup
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier shadowtwin-prod \
  --target-db-instance-identifier shadowtwin-restored \
  --restore-time 2025-12-15T10:00:00Z \
  --db-instance-class db.t3.medium

# Or restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier shadowtwin-restored \
  --db-snapshot-identifier shadowtwin-pre-migration-20251215
```

### Blue-Green Deployment (Zero-Downtime Rollback)

```bash
# Create new target group for rollback version
aws elbv2 create-target-group \
  --name shadowtwin-tg-blue \
  --protocol HTTP \
  --port 5000 \
  --vpc-id vpc-xxx

# Deploy rollback version to new target group
# ...

# Switch traffic (instant rollback)
aws elbv2 modify-listener \
  --listener-arn arn:aws:elasticloadbalancing:... \
  --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:.../shadowtwin-tg-blue/xxx
```

### Rollback Decision Matrix

| Issue | Rollback Method | Time Estimate |
|-------|-----------------|---------------|
| Application bug | ECS task definition rollback | 5-10 min |
| Database migration issue | RDS point-in-time restore | 30-60 min |
| Configuration error | Update secrets + redeploy | 5-10 min |
| Infrastructure failure | Blue-green switch | 2-5 min |

---

## Contact & Handover

For questions about this deployment guide or the ShadowTwin platform, contact:

- **Technical Lead**: [Your Contact]
- **DevOps Support**: [Support Contact]
- **Documentation Version**: 1.1
- **Last Updated**: December 2025
