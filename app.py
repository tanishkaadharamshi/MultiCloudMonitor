import os
import re
import time
import smtplib
import logging
from email.message import EmailMessage
from threading import Lock
from datetime import datetime, timedelta, timezone

import boto3
from dotenv import load_dotenv
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from flask import (
    Flask, request, redirect, url_for, flash,
    render_template_string, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# CONFIGURATION
# =========================================================

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-development-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///multicloudmonitor.db"
).replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

logging.basicConfig(level=logging.INFO)

REGIONS = {
    "ap-south-1": "Mumbai",
    "ap-southeast-1": "Singapore",
    "us-east-1": "N. Virginia",
    "eu-west-1": "Ireland",
}

CPU_ALERT_THRESHOLD = float(os.getenv("CPU_ALERT_THRESHOLD", "80"))
MEMORY_ALERT_THRESHOLD = float(os.getenv("MEMORY_ALERT_THRESHOLD", "80"))

HISTORY_HOURS = 3
COST_DAYS = 30
COST_CACHE_SECONDS = 3600
ALERT_COOLDOWN_SECONDS = 1800

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", SMTP_USER)
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")

AWS_CONFIG = Config(
    connect_timeout=5,
    read_timeout=20,
    retries={"max_attempts": 2, "mode": "standard"},
)

_cost_cache = {"time": 0, "data": None}
_alert_lock = Lock()
_last_email_alert = {}

# S3 details need several AWS calls per bucket, so cache them.
S3_CACHE_SECONDS = 600
_s3_cache = {"time": 0, "data": None, "errors": []}


# =========================================================
# DATABASE
# =========================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    region = db.Column(db.String(30), nullable=False, default="ap-south-1")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


with app.app_context():
    db.create_all()

    # create_all() creates missing tables but does not add columns to an
    # existing table. Older installs may have users without a saved region.
    user_columns = {
        column["name"]
        for column in db.inspect(db.engine).get_columns(User.__tablename__)
    }
    if "region" not in user_columns:
        quoted_table = db.engine.dialect.identifier_preparer.quote(
            User.__tablename__
        )
        with db.engine.begin() as connection:
            connection.exec_driver_sql(
                f"ALTER TABLE {quoted_table} "
                "ADD COLUMN region VARCHAR(30) "
                "NOT NULL DEFAULT 'ap-south-1'"
            )
        app.logger.info("Added missing region column to the user table.")


# =========================================================
# AWS HELPERS
# =========================================================

def aws_client(service, region=None):
    return boto3.client(service, region_name=region, config=AWS_CONFIG)


def aws_error_message(error):
    if isinstance(error, ClientError):
        return error.response.get("Error", {}).get(
            "Message", "AWS request failed."
        )
    return str(error)


def fmt_time(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return "-"


def average(values):
    return round(sum(values) / len(values), 2) if values else None


def fetch_metric_series(cw, queries):
    series = {}
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=HISTORY_HOURS)

    for i in range(0, len(queries), 450):
        token = None
        chunk = queries[i:i + 450]

        while True:
            kwargs = {
                "MetricDataQueries": chunk,
                "StartTime": start,
                "EndTime": end,
                "ScanBy": "TimestampAscending",
            }
            if token:
                kwargs["NextToken"] = token

            response = cw.get_metric_data(**kwargs)

            for item in response.get("MetricDataResults", []):
                series.setdefault(item["Id"], []).extend(
                    zip(item.get("Timestamps", []), item.get("Values", []))
                )

            token = response.get("NextToken")
            if not token:
                break

    for key in series:
        series[key].sort(key=lambda point: point[0])

    return series


def get_memory_dimensions(cw):
    found = {}
    paginator = cw.get_paginator("list_metrics")

    for page in paginator.paginate(
        Namespace="CWAgent",
        MetricName="mem_used_percent"
    ):
        for metric in page.get("Metrics", []):
            dimensions = metric.get("Dimensions", [])
            instance_id = next(
                (
                    d["Value"] for d in dimensions
                    if d["Name"] == "InstanceId"
                ),
                None
            )
            if instance_id and instance_id not in found:
                found[instance_id] = dimensions

    return found


def get_cost_data():
    now = time.time()

    if (
        _cost_cache["data"] is not None
        and now - _cost_cache["time"] < COST_CACHE_SECONDS
    ):
        return _cost_cache["data"]

    ce = aws_client("ce", "us-east-1")
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=COST_DAYS)

    by_service = {}
    token = None

    while True:
        kwargs = {
            "TimePeriod": {
                "Start": start.isoformat(),
                "End": end.isoformat(),
            },
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
            "Filter": {
                "Not": {
                    "Dimensions": {
                        "Key": "RECORD_TYPE",
                        "Values": ["Credit", "Refund"],
                    }
                }
            },
        }

        if token:
            kwargs["NextPageToken"] = token

        response = ce.get_cost_and_usage(**kwargs)

        for day in response.get("ResultsByTime", []):
            for group in day.get("Groups", []):
                service = group["Keys"][0]
                amount = float(
                    group["Metrics"]["UnblendedCost"]["Amount"]
                )
                by_service[service] = by_service.get(service, 0.0) + amount

        token = response.get("NextPageToken")
        if not token:
            break

    total = sum(by_service.values())

    services = sorted(
        [
            {"service": name, "cost": round(value, 2)}
            for name, value in by_service.items()
            if abs(value) >= 0.005
        ],
        key=lambda item: item["cost"],
        reverse=True,
    )

    data = {
        "total": round(total, 2),
        "services": services[:10],
        "start": start.isoformat(),
        "end": (end - timedelta(days=1)).isoformat(),
    }

    _cost_cache["time"] = now
    _cost_cache["data"] = data
    return data


# ---------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------

def fmt_bytes(value):
    if value is None:
        return "No data yet"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024


def get_s3_metrics(name, region):
    """Latest daily size and object count from CloudWatch."""
    cw = aws_client("cloudwatch", region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=3)

    def query(query_id, metric, storage_type):
        return {
            "Id": query_id,
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/S3",
                    "MetricName": metric,
                    "Dimensions": [
                        {"Name": "BucketName", "Value": name},
                        {"Name": "StorageType", "Value": storage_type},
                    ],
                },
                "Period": 86400,
                "Stat": "Average",
            },
            "ReturnData": True,
        }

    response = cw.get_metric_data(
        MetricDataQueries=[
            query("size", "BucketSizeBytes", "StandardStorage"),
            query("objects", "NumberOfObjects", "AllStorageTypes"),
        ],
        StartTime=start,
        EndTime=end,
        ScanBy="TimestampDescending",
    )
    values = {
        item["Id"]: item.get("Values", [])
        for item in response.get("MetricDataResults", [])
    }
    size = values.get("size") or []
    objects = values.get("objects") or []
    return (
        size[0] if size else None,
        int(objects[0]) if objects else None,
    )


def get_bucket_public_status(s3, name):
    try:
        config = s3.get_public_access_block(Bucket=name)[
            "PublicAccessBlockConfiguration"
        ]
        return "Blocked" if all(config.values()) else "Partially open"
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            return "Not blocked"
        return "Unknown"
    except BotoCoreError:
        return "Unknown"


def get_s3_data():
    now = time.time()
    if (
        _s3_cache["data"] is not None
        and now - _s3_cache["time"] < S3_CACHE_SECONDS
    ):
        return _s3_cache["data"], _s3_cache["errors"]

    buckets, errors = [], []
    s3 = aws_client("s3")

    def add_error(message):
        if message not in errors:
            errors.append(message)

    for page in s3.get_paginator("list_buckets").paginate():
        for bucket in page.get("Buckets", []):
            name = bucket["Name"]
            region = "Unknown"
            size_bytes = objects = None
            versioning = "Unknown"

            try:
                location = s3.get_bucket_location(Bucket=name).get(
                    "LocationConstraint"
                )
                region = "eu-west-1" if location == "EU" else (location or "us-east-1")
            except (ClientError, BotoCoreError) as error:
                add_error("S3 bucket location: " + aws_error_message(error))

            if region != "Unknown":
                try:
                    size_bytes, objects = get_s3_metrics(name, region)
                except (ClientError, BotoCoreError) as error:
                    add_error("S3 bucket metrics: " + aws_error_message(error))

            try:
                status = s3.get_bucket_versioning(Bucket=name).get("Status")
                versioning = status or "Off"
            except (ClientError, BotoCoreError) as error:
                add_error("S3 bucket versioning: " + aws_error_message(error))

            buckets.append({
                "name": name,
                "region": region,
                "created": fmt_time(bucket.get("CreationDate")),
                "size": fmt_bytes(size_bytes),
                "objects": objects,
                "versioning": versioning,
                "public": get_bucket_public_status(s3, name),
            })

    _s3_cache["time"] = now
    _s3_cache["data"] = buckets
    _s3_cache["errors"] = errors
    return buckets, errors


# ---------------------------------------------------------
# Email alerts
# ---------------------------------------------------------

def send_email_alert(subject, message):
    if not all([
        SMTP_HOST,
        SMTP_USER,
        SMTP_PASSWORD,
        ALERT_EMAIL_FROM,
        ALERT_EMAIL_TO,
    ]):
        return False, "Email is not configured."

    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = ALERT_EMAIL_FROM
    email["To"] = ALERT_EMAIL_TO
    email.set_content(message)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(email)

        return True, "Email sent."

    except (OSError, smtplib.SMTPException) as error:
        app.logger.warning("Email alert failed: %s", error)
        return False, "Email could not be sent."


def dispatch_alert_emails(region, alerts):
    """Email high CPU alerts with a per-process cooldown."""
    now = time.time()

    for alert in alerts:
        if alert.get("title") not in (
            "High CPU usage",
            "High memory usage",
            "Unused EBS volume",
        ):
            continue

        key = f'{region}:{alert["title"]}:{alert["message"].split(" latest ")[0].split(" memory usage is ")[0]}'

        with _alert_lock:
            last_sent = _last_email_alert.get(key, 0)
            if now - last_sent < ALERT_COOLDOWN_SECONDS:
                continue

            # Only set the cooldown after a successful send.
            if not all([
                SMTP_HOST, SMTP_USER, SMTP_PASSWORD,
                ALERT_EMAIL_FROM, ALERT_EMAIL_TO
            ]):
                continue

        sent, message = send_email_alert(
            f'MultiCloudMonitor: {alert["title"]}',
            f'Region: {region}\n'
            f'{alert["message"]}\n\n'
            'Please check your AWS monitoring dashboard.'
        )

        if sent:
            with _alert_lock:
                _last_email_alert[key] = now
        else:
            app.logger.warning("Alert notification: %s", message)


# =========================================================
# MULTI-REGION SUMMARY
# =========================================================

def get_multi_region_summary():
    summary = []

    for region, region_name in REGIONS.items():
        item = {
            "region": region,
            "name": region_name,
            "instances": 0,
            "running": 0,
            "stopped": 0,
            "status": "Connected",
            "error": None,
        }

        try:
            ec2 = aws_client("ec2", region)
            paginator = ec2.get_paginator("describe_instances")

            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        item["instances"] += 1
                        state = instance.get("State", {}).get("Name")

                        if state == "running":
                            item["running"] += 1
                        elif state == "stopped":
                            item["stopped"] += 1

        except (ClientError, BotoCoreError) as error:
            item["status"] = "Unavailable"
            item["error"] = aws_error_message(error)

        summary.append(item)

    return summary


# =========================================================
# RESOURCE MONITORING
# =========================================================

def get_resource_data(region):
    result = {
        "instances": [],
        "volumes": [],
        "buckets": [],
        "rds_instances": [],
        "lambdas": [],
        "snapshots": [],
        "snapshot_count": 0,
        "cost": None,
        "errors": [],
        "service_status": {},
        "suggestions": [],
        "alerts": [],
        "chart": {"labels": [], "datasets": []},
        "memory_available": False,
    }

    ec2 = aws_client("ec2", region)
    cw = aws_client("cloudwatch", region)
    raw_instances = []

    # EC2
    try:
        paginator = ec2.get_paginator("describe_instances")

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = {
                        tag["Key"]: tag["Value"]
                        for tag in instance.get("Tags", [])
                    }

                    raw_instances.append({
                        "id": instance["InstanceId"],
                        "name": tags.get("Name", "Unnamed"),
                        "type": instance.get("InstanceType", "-"),
                        "state": instance.get("State", {}).get("Name", "unknown"),
                        "az": instance.get("Placement", {}).get(
                            "AvailabilityZone", "-"
                        ),
                        "launch_time": fmt_time(instance.get("LaunchTime")),
                    })

    except (ClientError, BotoCoreError) as error:
        result["errors"].append("EC2: " + aws_error_message(error))

    # CloudWatch CPU, network and optional memory
    series = {}
    memory_dims = {}

    if raw_instances:
        try:
            memory_dims = get_memory_dimensions(cw)
        except (ClientError, BotoCoreError) as error:
            result["errors"].append(
                "CloudWatch memory lookup: " + aws_error_message(error)
            )

        queries = []

        for index, instance in enumerate(raw_instances):
            dimensions = [{
                "Name": "InstanceId",
                "Value": instance["id"],
            }]

            for prefix, metric, statistic in [
                ("cpu", "CPUUtilization", "Average"),
                ("nin", "NetworkIn", "Sum"),
                ("nout", "NetworkOut", "Sum"),
            ]:
                queries.append({
                    "Id": f"{prefix}{index}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/EC2",
                            "MetricName": metric,
                            "Dimensions": dimensions,
                        },
                        "Period": 300,
                        "Stat": statistic,
                    },
                    "ReturnData": True,
                })

            if instance["id"] in memory_dims:
                queries.append({
                    "Id": f"mem{index}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "CWAgent",
                            "MetricName": "mem_used_percent",
                            "Dimensions": memory_dims[instance["id"]],
                        },
                        "Period": 300,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                })

        try:
            series = fetch_metric_series(cw, queries)
        except (ClientError, BotoCoreError) as error:
            result["errors"].append(
                "CloudWatch metrics: " + aws_error_message(error)
            )

    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    chart_times = set()
    chart_series = []

    for index, instance in enumerate(raw_instances):
        cpu_points = series.get(f"cpu{index}", [])
        network_in_points = series.get(f"nin{index}", [])
        network_out_points = series.get(f"nout{index}", [])
        memory_points = series.get(f"mem{index}", [])

        recent_cpu = [
            value for timestamp, value in cpu_points
            if timestamp >= one_hour_ago
        ]
        recent_in = [
            value for timestamp, value in network_in_points
            if timestamp >= one_hour_ago
        ]
        recent_out = [
            value for timestamp, value in network_out_points
            if timestamp >= one_hour_ago
        ]

        instance["cpu"] = average(recent_cpu)
        instance["cpu_latest"] = (
            round(cpu_points[-1][1], 2) if cpu_points else None
        )
        instance["network_in"] = (
            round(sum(recent_in) / 1048576, 2) if recent_in else None
        )
        instance["network_out"] = (
            round(sum(recent_out) / 1048576, 2) if recent_out else None
        )
        instance["memory"] = (
            round(memory_points[-1][1], 2) if memory_points else None
        )

        if instance["memory"] is not None:
            result["memory_available"] = True

        result["instances"].append(instance)

        if cpu_points:
            chart_series.append((
                f'{instance["name"]} ({instance["id"]})',
                cpu_points,
            ))
            chart_times.update(timestamp for timestamp, _ in cpu_points)

        if (
            instance["cpu_latest"] is not None
            and instance["cpu_latest"] >= CPU_ALERT_THRESHOLD
        ):
            result["alerts"].append({
                "level": "danger",
                "title": "High CPU usage",
                "message": (
                    f'{instance["name"]} ({instance["id"]}) '
                    f'latest CPU is {instance["cpu_latest"]}%.'
                ),
            })

        if (
            instance["memory"] is not None
            and instance["memory"] >= MEMORY_ALERT_THRESHOLD
        ):
            result["alerts"].append({
                "level": "danger",
                "title": "High memory usage",
                "message": (
                    f'{instance["name"]} ({instance["id"]}) '
                    f'memory usage is {instance["memory"]}%.'
                ),
            })

    sorted_times = sorted(chart_times)
    result["chart"]["labels"] = [
        timestamp.isoformat() for timestamp in sorted_times
    ]

    for label, points in chart_series:
        lookup = {
            timestamp: round(value, 2)
            for timestamp, value in points
        }

        result["chart"]["datasets"].append({
            "label": label,
            "data": [lookup.get(timestamp) for timestamp in sorted_times],
        })

    # EBS volumes
    try:
        paginator = ec2.get_paginator("describe_volumes")

        for page in paginator.paginate():
            for volume in page.get("Volumes", []):
                attachments = volume.get("Attachments", [])

                item = {
                    "id": volume["VolumeId"],
                    "size": volume.get("Size", 0),
                    "type": volume.get("VolumeType", "-"),
                    "state": volume.get("State", "-"),
                    "az": volume.get("AvailabilityZone", "-"),
                    "encrypted": "Yes" if volume.get("Encrypted") else "No",
                    "attached_to": ", ".join(
                        attachment.get("InstanceId", "")
                        for attachment in attachments
                    ) or "None",
                }

                result["volumes"].append(item)

                if volume.get("State") == "available":
                    result["alerts"].append({
                        "level": "warning",
                        "title": "Unused EBS volume",
                        "message": (
                            f'{volume["VolumeId"]} ({item["size"]} GiB) '
                            'is unattached. Check whether it is still needed.'
                        ),
                    })

    except (ClientError, BotoCoreError) as error:
        result["errors"].append("EBS: " + aws_error_message(error))

    # Snapshots
    try:
        paginator = ec2.get_paginator("describe_snapshots")

        for page in paginator.paginate(OwnerIds=["self"]):
            for snapshot in page.get("Snapshots", []):
                result["snapshot_count"] += 1

                if len(result["snapshots"]) < 20:
                    result["snapshots"].append({
                        "id": snapshot["SnapshotId"],
                        "volume": snapshot.get("VolumeId", "-"),
                        "size": snapshot.get("VolumeSize", 0),
                        "state": snapshot.get("State", "-"),
                        "started": fmt_time(snapshot.get("StartTime")),
                    })

    except (ClientError, BotoCoreError) as error:
        result["errors"].append("Snapshots: " + aws_error_message(error))

    # S3 buckets (account-wide, cached)
    try:
        buckets, s3_errors = get_s3_data()
        result["buckets"] = buckets
        result["errors"].extend(s3_errors)
    except (ClientError, BotoCoreError) as error:
        result["errors"].append("S3: " + aws_error_message(error))

    # RDS
    try:
        rds = aws_client("rds", region)
        paginator = rds.get_paginator("describe_db_instances")

        for page in paginator.paginate():
            for item in page.get("DBInstances", []):
                result["rds_instances"].append({
                    "id": item["DBInstanceIdentifier"],
                    "engine": item.get("Engine", "-"),
                    "class": item.get("DBInstanceClass", "-"),
                    "status": item.get("DBInstanceStatus", "-"),
                    "storage": item.get("AllocatedStorage", 0),
                })

    except (ClientError, BotoCoreError) as error:
        result["errors"].append("RDS: " + aws_error_message(error))

    # Lambda
    try:
        lam = aws_client("lambda", region)
        paginator = lam.get_paginator("list_functions")

        for page in paginator.paginate():
            for function in page.get("Functions", []):
                result["lambdas"].append({
                    "name": function["FunctionName"],
                    "runtime": function.get("Runtime") or "-",
                    "memory": function.get("MemorySize", 0),
                    "timeout": function.get("Timeout", 0),
                })

    except (ClientError, BotoCoreError) as error:
        result["errors"].append("Lambda: " + aws_error_message(error))

    # Cost Explorer
    try:
        result["cost"] = get_cost_data()

    except (ClientError, BotoCoreError) as error:
        result["errors"].append(
            "Cost Explorer: " + aws_error_message(error)
        )

    result["alerts"].sort(
        key=lambda alert: 0 if alert["level"] == "danger" else 1
    )

    dispatch_alert_emails(region, result["alerts"])

    # Make per-service access explicit, including successful empty responses.
    service_prefixes = {
        "EC2": ("EC2:",),
        "CloudWatch": ("CloudWatch ",),
        "EBS": ("EBS:",),
        "Snapshots": ("Snapshots:",),
        "S3": ("S3:", "S3 bucket"),
        "RDS": ("RDS:",),
        "Lambda": ("Lambda:",),
        "Cost Explorer": ("Cost Explorer:",),
    }
    for service, prefixes in service_prefixes.items():
        result["service_status"][service] = (
            "Error" if any(error.startswith(prefix) for error in result["errors"] for prefix in prefixes)
            else "Connected"
        )

    unattached = [v for v in result["volumes"] if v["state"] == "available"]
    if unattached:
        result["suggestions"].append({
            "title": "Review unattached EBS volumes",
            "detail": f"{len(unattached)} volume(s) are unattached and may still incur storage charges.",
        })
    low_cpu = [i for i in result["instances"] if i.get("cpu") is not None and i["cpu"] < 5 and i["state"] == "running"]
    if low_cpu:
        result["suggestions"].append({
            "title": "Review low-CPU instances",
            "detail": f"{len(low_cpu)} running instance(s) averaged below 5% CPU over the last hour. Check workload patterns before resizing or stopping.",
        })
    if result["cost"] and result["cost"]["total"] == 0 and not result["cost"]["services"]:
        result["cost"]["no_usage"] = True

    return result


# =========================================================
# STYLES AND TEMPLATES
# =========================================================

BASE_STYLE = """
<style>
* { box-sizing: border-box; }
body {
    margin: 0; font-family: Arial, Helvetica, sans-serif;
    background: #f3f5f9; color: #1f2937;
}
header {
    background: #1e293b; color: white; padding: 14px 28px;
    display: flex; justify-content: space-between;
    align-items: center; gap: 12px; flex-wrap: wrap;
}
header h1 { margin: 0; font-size: 22px; }
header a {
    color: white; text-decoration: none; background: #334155;
    padding: 7px 14px; border-radius: 6px;
}
main { max-width: 1250px; margin: 24px auto; padding: 0 16px; }
.card {
    background: white; border-radius: 10px; padding: 20px;
    margin-bottom: 20px; box-shadow: 0 1px 4px #00000012;
}
.card h2 { margin: 0 0 12px; font-size: 18px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid #e5e7eb; }
th { background: #f8fafc; }
.table-wrap { overflow-x: auto; }
.muted { color: #6b7280; font-size: 13px; }
.badge { padding: 3px 9px; border-radius: 12px; font-size: 12px; font-weight: bold; }
.running, .available, .completed { background: #dcfce7; color: #166534; }
.stopped, .terminated { background: #fee2e2; color: #991b1b; }
.other { background: #fef3c7; color: #92400e; }
.alert { padding: 10px 14px; border-radius: 8px; margin-bottom: 8px; font-size: 14px; overflow-wrap: anywhere; }
.alert.danger { background: #fee2e2; border-left: 5px solid #dc2626; }
.alert.warning { background: #fef3c7; border-left: 5px solid #d97706; }
.alert.ok { background: #dcfce7; border-left: 5px solid #16a34a; }
.flash { padding: 10px 14px; border-radius: 8px; margin-bottom: 14px; background: #dbeafe; }
.flash.error { background: #fee2e2; }
.flash.success { background: #dcfce7; }
input, select, button {
    padding: 9px 12px; font-size: 14px; border-radius: 6px;
    border: 1px solid #cbd5e1; max-width: 100%;
}
button { background: #2563eb; color: white; border: none; cursor: pointer; }
button:hover { background: #1d4ed8; }
.big { font-size: 28px; font-weight: bold; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; }
.stat { background: #f8fafc; border-radius: 8px; padding: 14px; text-align: center; }
.stat span { display: block; font-size: 26px; font-weight: bold; color: #2563eb; }
.auth { max-width: 380px; margin: 70px auto; }
.auth input { width: 100%; margin-bottom: 12px; }
.auth button { width: 100%; }
#typeSearch { width: 100%; max-width: 450px; }
.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
canvas { max-width: 100%; }
details > summary { cursor: pointer; font-weight: bold; padding: 10px 0; }
details[open] > summary { margin-bottom: 8px; }
</style>
"""

AUTH_TEMPLATE = """
<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - MultiCloudMonitor</title>
""" + BASE_STYLE + """
</head><body>
<main class="auth">
  <div class="card">
    <h2>MultiCloudMonitor</h2>
    <p class="muted">{{ title }}</p>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    <form method="post">
      {% if title == "Register" %}
        <input name="username" placeholder="Username" minlength="3" maxlength="50" required autofocus>
      {% endif %}
      <input name="email" type="email" placeholder="Email" maxlength="120" required {% if title == "Login" %}autofocus{% endif %}>
      <input name="password" type="password" placeholder="Password" minlength="8" required>
      <button type="submit">{{ title }}</button>
    </form>
    <p class="muted">
      {% if title == "Login" %}
        New here? <a href="{{ url_for('register') }}">Create an account</a>
      {% else %}
        Already registered? <a href="{{ url_for('login') }}">Login</a>
      {% endif %}
    </p>
  </div>
</main>
</body></html>
"""

DASHBOARD_TEMPLATE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MultiCloudMonitor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
""" + BASE_STYLE + """
</head>
<body>
<header>
  <h1>MultiCloudMonitor</h1>
  <div>Welcome, {{ user.username }}! &nbsp;
    <a href="{{ url_for('logout') }}">Logout</a>
  </div>
</header>

<main>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% for category, message in messages %}
    <div class="flash {{ category }}">{{ message }}</div>
  {% endfor %}
{% endwith %}

<div class="card">
  <h2>AWS Region Selection</h2>
  <form method="post" action="{{ url_for('save_region') }}" class="controls">
    <label for="region">Select region:</label>
    <select id="region" name="region">
      {% for code, name in regions.items() %}
        <option value="{{ code }}" {% if code == user.region %}selected{% endif %}>
          {{ name }} ({{ code }})
        </option>
      {% endfor %}
    </select>
    <button type="submit">Save Region</button>
  </form>
  <p class="muted">Detailed monitoring region: {{ user.region }}</p>
</div>

<div class="card">
  <h2>Multi-Region EC2 Summary</h2>
  <p class="muted">Instance counts across all four configured AWS regions.</p>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Region</th><th>Total Instances</th><th>Running</th><th>Stopped</th><th>Status</th></tr>
      </thead>
      <tbody>
      {% for r in multi_region_summary %}
        <tr>
          <td>{{ r.name }} ({{ r.region }})</td>
          <td>{{ r.instances }}</td>
          <td>{{ r.running }}</td>
          <td>{{ r.stopped }}</td>
          <td>
            {% if r.status == "Connected" %}
              <span class="badge available">Connected</span>
            {% else %}
              <span class="badge other">Unavailable</span>
              <div class="muted">{{ r.error }}</div>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>

<div class="card">
  <h2>AWS Connection and Resource Summary</h2>
  {% if data.errors and not data.instances and not data.volumes %}
    <div class="alert danger">Some AWS data could not be retrieved. See access messages below.</div>
  {% else %}
    <div class="alert ok">Dashboard loaded. Individual service errors are shown separately.</div>
  {% endif %}
  <div class="grid">
    <div class="stat"><span>{{ data.instances|length }}</span>EC2 instances</div>
    <div class="stat"><span>{{ data.volumes|length }}</span>EBS volumes</div>
    <div class="stat"><span>{{ data.buckets|length }}</span>S3 buckets</div>
    <div class="stat"><span>{{ data.rds_instances|length }}</span>RDS databases</div>
    <div class="stat"><span>{{ data.lambdas|length }}</span>Lambda functions</div>
    <div class="stat"><span>{{ data.snapshot_count }}</span>Snapshots</div>
  </div>
  <h3>Service connection status ({{ user.region }})</h3>
  <div class="grid">
    {% for service, status in data.service_status.items() %}
      <div class="stat"><strong>{{ service }}</strong><br>
        <span class="badge {{ 'available' if status == 'Connected' else 'stopped' }}">{{ status }}</span>
      </div>
    {% endfor %}
  </div>
</div>

{% if data.errors %}
<div class="card">
  <h2>Resource Access Messages</h2>
  {% for error in data.errors %}
    <div class="alert warning">{{ error }}</div>
  {% endfor %}
  <p class="muted">Check the relevant IAM permissions if an AWS service is unavailable.</p>
</div>
{% endif %}

<div class="card">
  <h2>Alerts</h2>
  {% if data.alerts %}
    {% for alert in data.alerts %}
      <div class="alert {{ alert.level }}">
        <strong>{{ alert.title }}:</strong> {{ alert.message }}
      </div>
    {% endfor %}
  {% else %}
    <div class="alert ok">No current CPU, memory or unattached-volume alerts were detected.</div>
  {% endif %}
  <p class="muted">
    CPU threshold: {{ cpu_threshold }}%.
    Memory threshold: {{ mem_threshold }}%.
    Alerts are evaluated when the dashboard loads.
  </p>
  <p class="muted">
    Email status:
    {% if email_configured %}
      SMTP settings are present. Delivery still depends on the mail server.
    {% else %}
      Not configured. Dashboard alerts remain available.
    {% endif %}
  </p>
</div>

<div class="card">
  <h2>Cost optimization suggestions</h2>
  {% if data.suggestions %}
    {% for suggestion in data.suggestions %}
      <div class="alert warning"><strong>{{ suggestion.title }}:</strong> {{ suggestion.detail }}</div>
    {% endfor %}
  {% else %}
    <p class="muted">No obvious opportunities found from the resources and recent CPU metrics available in this region.</p>
  {% endif %}
  <p class="muted">Suggestions are indicators for review; validate workload and retention needs before changing resources.</p>
</div>

<div class="card">
  <h2>AWS IAM permissions to check</h2>
  <p class="muted">Attach permissions to the app's IAM role or AWS credentials. AWS errors above show which service call failed.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Feature</th><th>Actions commonly required</th></tr></thead>
    <tbody>
      <tr><td>EC2, EBS, snapshots, instance types</td><td>ec2:DescribeInstances, ec2:DescribeVolumes, ec2:DescribeSnapshots, ec2:DescribeInstanceTypes</td></tr>
      <tr><td>CPU, network, memory metrics</td><td>cloudwatch:GetMetricData, cloudwatch:ListMetrics; CWAgent must publish memory metrics</td></tr>
      <tr><td>S3</td><td>s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketPublicAccessBlock, s3:GetBucketVersioning, cloudwatch:GetMetricData (for size and object counts)</td></tr>
      <tr><td>RDS and Lambda</td><td>rds:DescribeDBInstances, lambda:ListFunctions</td></tr>
      <tr><td>30-day cost</td><td>ce:GetCostAndUsage; Cost Explorer must be enabled for the account</td></tr>
    </tbody>
  </table></div>
</div>

<div class="card">
  <h2>EC2 Resource Monitoring</h2>
  {% if data.instances %}
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Instance Name / ID</th><th>Type / AZ</th><th>State</th>
          <th>Average CPU (1h)</th><th>Latest CPU</th><th>Memory</th>
          <th>Network In (1h)</th><th>Network Out (1h)</th>
        </tr>
      </thead>
      <tbody>
      {% for i in data.instances %}
        <tr>
          <td><strong>{{ i.name }}</strong><br><span class="muted">{{ i.id }}</span></td>
          <td>{{ i.type }}<br><span class="muted">{{ i.az }}</span></td>
          <td><span class="badge {{ i.state if i.state in ['running','stopped','terminated'] else 'other' }}">{{ i.state }}</span></td>
          <td>{{ (i.cpu ~ '%') if i.cpu is not none else 'No data' }}</td>
          <td>{{ (i.cpu_latest ~ '%') if i.cpu_latest is not none else 'No data' }}</td>
          <td>{{ (i.memory ~ '%') if i.memory is not none else 'Not available' }}</td>
          <td>{{ (i.network_in ~ ' MB') if i.network_in is not none else 'No data' }}</td>
          <td>{{ (i.network_out ~ ' MB') if i.network_out is not none else 'No data' }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% if not data.memory_available %}
    <p class="muted">Memory monitoring requires the CloudWatch Agent to publish CWAgent/mem_used_percent.</p>
  {% endif %}
  {% else %}
    <p class="muted">No EC2 instances found in this region, or access is unavailable.</p>
  {% endif %}
</div>

<div class="card">
  <h2>CPU Utilization History (last {{ history_hours }} hours)</h2>
  {% if data.chart.datasets %}
    <canvas id="cpuChart" height="110"></canvas>
  {% else %}
    <p class="muted">No CPU readings available yet.</p>
  {% endif %}
</div>

<div class="card">
  <h2>EBS Volumes</h2>
  {% if data.volumes %}
  <div class="table-wrap">
    <table>
      <thead><tr><th>Volume ID</th><th>Size</th><th>Type</th><th>State</th><th>Attached To</th><th>Encrypted</th><th>AZ</th></tr></thead>
      <tbody>
      {% for v in data.volumes %}
        <tr>
          <td>{{ v.id }}</td><td>{{ v.size }} GiB</td><td>{{ v.type }}</td>
          <td><span class="badge {{ 'available' if v.state == 'in-use' else 'other' }}">{{ v.state }}</span></td>
          <td>{{ v.attached_to }}</td><td>{{ v.encrypted }}</td><td>{{ v.az }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
    <p class="muted">No EBS volumes found in this region.</p>
  {% endif %}
</div>

<div class="card">
  <h2>AWS Cost Monitoring</h2>
  {% if data.cost and data.cost.no_usage %}
    <p class="muted">Cost Explorer returned no non-zero service charges for this period. No dollar amount is shown; verify Cost Explorer activation, billing permissions and account data.</p>
    <p class="muted">Last {{ cost_days }} days: {{ data.cost.start }} to {{ data.cost.end }}. Account-wide, refreshed hourly.</p>
  {% elif data.cost %}
    <div class="big">${{ '%.2f'|format(data.cost.total) }} USD</div>
    <p class="muted">
      Last {{ cost_days }} days: {{ data.cost.start }} to {{ data.cost.end }}.
      Account-wide, excluding credits and refunds. Refreshed hourly.
    </p>
    {% if data.cost.services %}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Service</th><th>Cost (USD)</th></tr></thead>
        <tbody>
        {% for s in data.cost.services %}
          <tr><td>{{ s.service }}</td><td>${{ '%.2f'|format(s.cost) }}</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
      <p class="muted">No non-zero service costs were returned for this period.</p>
    {% endif %}
  {% else %}
    <p class="muted">Cost data unavailable. Check Cost Explorer activation and ce:GetCostAndUsage permission.</p>
  {% endif %}
</div>

<div class="card">
  <h2>Search EC2 Instance Types</h2>
  <p class="muted">
    Search or choose from the available types in {{ user.region }}. Select a type below to see its specifications.
  </p>
  <input id="typeSearch" type="search" placeholder="Try t3.micro, m7i, c6a..." autocomplete="off">
  <p id="typeMessage" class="muted" aria-live="polite">Enter at least two characters.</p>
  <div id="typeResultsWrap" style="display:none">
    <details id="typeResultsDetails">
      <summary id="typeResultsSummary">Show matching instance types</summary>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Instance Type</th><th>vCPUs</th><th>Memory (GiB)</th></tr></thead>
          <tbody id="typeResults"></tbody>
        </table>
      </div>
    </details>
  </div>
  <div class="controls" style="margin-top:16px">
    <label for="allTypesSelect">Available EC2 instance types:</label>
    <select id="allTypesSelect" aria-describedby="allTypesMessage">
      <option value="">Loading instance types...</option>
    </select>
  </div>
  <p id="allTypesMessage" class="muted" aria-live="polite">Loading types for {{ user.region }}...</p>
  <div id="selectedTypeSpecs" class="alert ok" style="display:none">
    <strong id="selectedTypeName"></strong> —
    <span id="selectedTypeVcpus"></span> vCPUs,
    <span id="selectedTypeMemory"></span> GiB memory
  </div>
</div>

<div class="card">
  <h2>Other AWS Resources</h2>
  <h3>RDS Databases</h3>
  {% if data.rds_instances %}
  <div class="table-wrap"><table>
    <thead><tr><th>Identifier</th><th>Engine</th><th>Class</th><th>Status</th><th>Storage</th></tr></thead>
    <tbody>{% for r in data.rds_instances %}
      <tr><td>{{ r.id }}</td><td>{{ r.engine }}</td><td>{{ r.class }}</td><td>{{ r.status }}</td><td>{{ r.storage }} GiB</td></tr>
    {% endfor %}</tbody>
  </table></div>
  {% else %}<p class="muted">No RDS instances found.</p>{% endif %}

  <h3>Lambda Functions</h3>
  {% if data.lambdas %}
  <div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Runtime</th><th>Memory</th><th>Timeout</th></tr></thead>
    <tbody>{% for l in data.lambdas %}
      <tr><td>{{ l.name }}</td><td>{{ l.runtime }}</td><td>{{ l.memory }} MB</td><td>{{ l.timeout }}s</td></tr>
    {% endfor %}</tbody>
  </table></div>
  {% else %}<p class="muted">No Lambda functions found.</p>{% endif %}

  <h3>S3 Buckets (account-wide)</h3>
  {% if data.buckets %}
  <div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Region</th><th>Size</th><th>Objects</th><th>Versioning</th><th>Public access</th><th>Created</th></tr></thead>
    <tbody>{% for b in data.buckets %}
      <tr>
        <td>{{ b.name }}</td>
        <td>{{ b.region }}</td>
        <td>{{ b.size }}</td>
        <td>{{ b.objects if b.objects is not none else 'No data yet' }}</td>
        <td>{{ b.versioning }}</td>
        <td><span class="badge {{ 'available' if b.public == 'Blocked' else ('other' if b.public == 'Unknown' else 'stopped') }}">{{ b.public }}</span></td>
        <td>{{ b.created }}</td>
      </tr>
    {% endfor %}</tbody>
  </table></div>
  <p class="muted">Size and object counts come from CloudWatch, which updates once a day, so new buckets show "No data yet". Refreshed every 10 minutes.</p>
  {% else %}<p class="muted">No S3 buckets found or access is unavailable.</p>{% endif %}

  <h3>EBS Snapshots (owned by this account; showing up to 20)</h3>
  {% if data.snapshots %}
  <div class="table-wrap"><table>
    <thead><tr><th>Snapshot</th><th>Volume</th><th>Size</th><th>State</th><th>Started</th></tr></thead>
    <tbody>{% for s in data.snapshots %}
      <tr><td>{{ s.id }}</td><td>{{ s.volume }}</td><td>{{ s.size }} GiB</td><td>{{ s.state }}</td><td>{{ s.started }}</td></tr>
    {% endfor %}</tbody>
  </table></div>
  {% else %}<p class="muted">No owned snapshots found.</p>{% endif %}
</div>
</main>

<script>
const chartData = {{ data.chart|tojson }};

if (chartData.datasets.length && window.Chart) {
  const labels = chartData.labels.map(t =>
    new Date(t).toLocaleTimeString([], {
      hour: "2-digit", minute: "2-digit"
    })
  );

  new Chart(document.getElementById("cpuChart"), {
    type: "line",
    data: {
      labels: labels,
      datasets: chartData.datasets.map(d => ({
        label: d.label,
        data: d.data,
        spanGaps: true,
        tension: 0.25,
        pointRadius: 2,
        borderWidth: 2
      }))
    },
    options: {
      responsive: true,
      interaction: { mode: "index", intersect: false },
      scales: {
        y: {
          min: 0, max: 100,
          title: { display: true, text: "CPU %" }
        },
        x: {
          title: { display: true, text: "Time (local)" }
        }
      }
    }
  });
} else if (chartData.datasets.length) {
  // Draw a lightweight SVG chart if the Chart.js CDN is unavailable.
  const host = document.getElementById("cpuChart");
  const width = Math.max(320, host.parentElement.clientWidth - 48);
  const height = 260, pad = 38;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", "100%"); svg.setAttribute("height", String(height));
  const line = (x1,y1,x2,y2,color="#cbd5e1") => {
    const e=document.createElementNS(ns,"line");
    for (const [k,v] of Object.entries({x1,y1,x2,y2,stroke:color})) e.setAttribute(k,v);
    svg.appendChild(e);
  };
  line(pad,pad,pad,height-pad); line(pad,height-pad,width-pad,height-pad);
  const colors=["#2563eb","#dc2626","#16a34a","#9333ea","#ea580c"];
  chartData.datasets.forEach((dataset,index) => {
    const valid=dataset.data.map((v,i)=>v==null?null:[i,Number(v)]).filter(Boolean);
    if (!valid.length) return;
    const denom=Math.max(1,chartData.labels.length-1);
    const points=valid.map(([i,v])=>`${pad+i/denom*(width-2*pad)},${height-pad-v/100*(height-2*pad)}`).join(" ");
    const poly=document.createElementNS(ns,"polyline");
    poly.setAttribute("points",points); poly.setAttribute("fill","none");
    poly.setAttribute("stroke",colors[index%colors.length]); poly.setAttribute("stroke-width","2.5");
    svg.appendChild(poly);
  });
  host.replaceWith(svg);
}

// Instance-type search: load results only after the user searches.
const searchBox = document.getElementById("typeSearch");
const typeMessage = document.getElementById("typeMessage");
const typeWrap = document.getElementById("typeResultsWrap");
const typeBody = document.getElementById("typeResults");
const typeDetails = document.getElementById("typeResultsDetails");
const typeSummary = document.getElementById("typeResultsSummary");
const allTypesSelect = document.getElementById("allTypesSelect");
const allTypesMessage = document.getElementById("allTypesMessage");
const selectedTypeSpecs = document.getElementById("selectedTypeSpecs");
const selectedTypeName = document.getElementById("selectedTypeName");
const selectedTypeVcpus = document.getElementById("selectedTypeVcpus");
const selectedTypeMemory = document.getElementById("selectedTypeMemory");
const allTypesByName = new Map();

let searchTimer = null;
let requestNumber = 0;
let controller = null;

function clearTypeResults(message) {
  typeBody.replaceChildren();
  typeWrap.style.display = "none";
  typeDetails.open = false;
  typeSummary.textContent = "Show matching instance types";
  typeMessage.textContent = message;
}

async function loadAllInstanceTypes() {
  allTypesMessage.textContent = "Loading all available instance types...";
  try {
    const response = await fetch("{{ url_for('api_instance_types') }}?all=1");
    const json = await response.json();
    if (!response.ok || json.error) {
      allTypesMessage.textContent = json.error || "Could not load instance types.";
      allTypesSelect.replaceChildren(new Option("Could not load types", ""));
      return;
    }

    allTypesSelect.replaceChildren(new Option("Choose an instance type...", ""));
    for (const row of json.results) {
      allTypesByName.set(row.type, row);
      allTypesSelect.add(new Option(
        `${row.type} — ${row.vcpus} vCPUs, ${row.memory} GiB`,
        row.type
      ));
    }
    allTypesMessage.textContent = json.results.length
      ? json.results.length + " instance type(s) available in this region."
      : "No instance types were returned for this region.";
  } catch (error) {
    allTypesMessage.textContent = "Could not load instance types. Please try again.";
  }
}

loadAllInstanceTypes();

allTypesSelect.addEventListener("change", function () {
  const selected = allTypesByName.get(allTypesSelect.value);
  if (!selected) {
    selectedTypeSpecs.style.display = "none";
    return;
  }
  selectedTypeName.textContent = selected.type;
  selectedTypeVcpus.textContent = selected.vcpus;
  selectedTypeMemory.textContent = selected.memory;
  selectedTypeSpecs.style.display = "block";
});

searchBox.addEventListener("input", function () {
  clearTimeout(searchTimer);

  if (controller) controller.abort();

  const query = searchBox.value.trim();

  if (query.length < 2) {
    requestNumber++;
    clearTypeResults("Enter at least two characters.");
    return;
  }

  searchTimer = setTimeout(() => searchTypes(query), 350);
});

async function searchTypes(query) {
  const thisRequest = ++requestNumber;
  controller = new AbortController();
  typeMessage.textContent = "Searching AWS...";
  typeWrap.style.display = "none";

  try {
    const response = await fetch(
      "{{ url_for('api_instance_types') }}?q=" + encodeURIComponent(query),
      { signal: controller.signal }
    );

    const json = await response.json();

    if (thisRequest !== requestNumber) return;

    if (!response.ok || json.error) {
      clearTypeResults(json.error || "Search failed.");
      return;
    }

    if (!json.results.length) {
      clearTypeResults("No matching instance types found in this region.");
      return;
    }

    typeBody.replaceChildren();

    for (const row of json.results) {
      const tr = document.createElement("tr");

      for (const value of [row.type, row.vcpus, row.memory]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
      }

      typeBody.appendChild(tr);
    }

    typeSummary.textContent = "Show " + json.results.length + " matching instance type(s)";
    typeDetails.open = false;
    typeWrap.style.display = "block";
    typeMessage.textContent = "Search results are collapsed. Expand the list when you need it.";
  } catch (error) {
    if (error.name !== "AbortError" && thisRequest === requestNumber) {
      clearTypeResults("Search failed. Please try again.");
    }
  }
}
</script>
</body>
</html>
"""


# =========================================================
# ROUTES
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 50:
            flash("Username must be 3 to 50 characters.", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif User.query.filter_by(username=username).first():
            flash("That username is already taken.", "error")
        elif User.query.filter_by(email=email).first():
            flash("That email is already registered.", "error")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

    return render_template_string(AUTH_TEMPLATE, title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template_string(AUTH_TEMPLATE, title="Login")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    region = (
        current_user.region
        if current_user.region in REGIONS
        else "ap-south-1"
    )

    data = get_resource_data(region)
    multi_region_summary = get_multi_region_summary()

    return render_template_string(
        DASHBOARD_TEMPLATE,
        user=current_user,
        regions=REGIONS,
        data=data,
        multi_region_summary=multi_region_summary,
        cpu_threshold=CPU_ALERT_THRESHOLD,
        mem_threshold=MEMORY_ALERT_THRESHOLD,
        history_hours=HISTORY_HOURS,
        cost_days=COST_DAYS,
        email_configured=bool(
            SMTP_HOST and SMTP_USER and SMTP_PASSWORD
            and ALERT_EMAIL_FROM and ALERT_EMAIL_TO
        ),
    )


@app.route("/region", methods=["POST"])
@login_required
def save_region():
    region = request.form.get("region", "")

    if region not in REGIONS:
        flash("Invalid region selected.", "error")
    else:
        current_user.region = region
        db.session.commit()
        flash(f"Region saved: {REGIONS[region]} ({region}).", "success")

    return redirect(url_for("dashboard"))


@app.route("/api/instance-types")
@login_required
def api_instance_types():
    query = request.args.get("q", "").strip().lower()
    show_all = request.args.get("all") == "1"

    if not show_all and len(query) < 2:
        return jsonify({
            "results": [],
            "error": "Enter at least two characters to search.",
        }), 400

    if query and not re.fullmatch(r"[a-z0-9.-]+", query):
        return jsonify({
            "results": [],
            "error": "Use letters, numbers, dots and hyphens only.",
        }), 400

    region = (
        current_user.region
        if current_user.region in REGIONS
        else "ap-south-1"
    )

    results = []

    try:
        ec2 = aws_client("ec2", region)

        # Use the API filter for the requested prefix or family.
        paginator = ec2.get_paginator("describe_instance_types")

        paginate_kwargs = {"PaginationConfig": {"PageSize": 100}}
        if query:
            paginate_kwargs["Filters"] = [{
                "Name": "instance-type",
                "Values": [f"*{query}*"],
            }]

        for page in paginator.paginate(**paginate_kwargs):
            for item in page.get("InstanceTypes", []):
                instance_type = item.get("InstanceType", "")

                # Client-side matching protects against unexpected filter behavior.
                if query and query not in instance_type.lower():
                    continue

                results.append({
                    "type": instance_type,
                    "vcpus": item.get("VCpuInfo", {}).get(
                        "DefaultVCpus", "-"
                    ),
                    "memory": round(
                        item.get("MemoryInfo", {}).get("SizeInMiB", 0) / 1024,
                        2,
                    ),
                })

    except (ClientError, BotoCoreError) as error:
        app.logger.warning("Instance type search failed: %s", error)
        return jsonify({
            "results": [],
            "error": "AWS search failed: " + aws_error_message(error),
        }), 502

    results.sort(key=lambda row: row["type"])

    return jsonify({
        "results": results,
        "truncated": False,
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
