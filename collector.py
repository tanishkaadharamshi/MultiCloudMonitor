import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

def _bucket_metric(cw, bucket, metric, storage_type):
    """Latest daily value of a CloudWatch S3 metric (0 if none yet)."""
    now = datetime.now(timezone.utc)
    resp = cw.get_metric_statistics(
        Namespace="AWS/S3",
        MetricName=metric,
        Dimensions=[
            {"Name": "BucketName", "Value": bucket},
            {"Name": "StorageType", "Value": storage_type},
        ],
        StartTime=now - timedelta(days=3),
        EndTime=now,
        Period=86400,
        Statistics=["Average"],
    )
    points = sorted(resp["Datapoints"], key=lambda p: p["Timestamp"])
    return points[-1]["Average"] if points else 0

def _is_public(s3, bucket):
    """True if the bucket does NOT fully block public access."""
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        return not all(cfg.values())
    except ClientError:
        return True  # no block configured

def get_s3_buckets():
    s3 = boto3.client("s3")
    buckets = []
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        try:
            region = s3.get_bucket_location(Bucket=name)["LocationConstraint"] or "us-east-1"
        except ClientError:
            continue

        cw = boto3.client("cloudwatch", region_name=region)
        size_bytes = _bucket_metric(cw, name, "BucketSizeBytes", "StandardStorage")
        objects = _bucket_metric(cw, name, "NumberOfObjects", "AllStorageTypes")

        buckets.append({
            "provider": "aws",
            "type": "s3",
            "id": name,
            "name": name,
            "region": region,
            "size_gb": round(size_bytes / 1024**3, 3),
            "objects": int(objects),
            "public": _is_public(s3, name),
            "created": b["CreationDate"].isoformat(),
        })
    return buckets