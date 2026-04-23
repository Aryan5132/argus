"""
Sentinel – AWS Client / Session Management
Supports real AWS credentials and optional mock/dry-run mode.
"""
import boto3
import logging
from botocore.exceptions import NoCredentialsError, ClientError
from backend.config import settings

logger = logging.getLogger(__name__)


class AWSClient:
    """Manages boto3 sessions and service clients."""

    def __init__(self):
        self._session = None
        self.region = settings.aws_default_region
        self.connected = False
        self._init_session()

    def _init_session(self):
        try:
            if settings.aws_access_key_id and settings.aws_secret_access_key:
                self._session = boto3.Session(
                    aws_access_key_id=settings.aws_access_key_id,
                    aws_secret_access_key=settings.aws_secret_access_key,
                    region_name=self.region,
                )
            else:
                # Fallback to environment / instance profile / ~/.aws/credentials
                self._session = boto3.Session(region_name=self.region)

            # Quick connectivity check
            sts = self._session.client("sts")
            identity = sts.get_caller_identity()
            self.account_id = identity["Account"]
            self.connected = True
            logger.info(f"✅ AWS connected – Account: {self.account_id}, Region: {self.region}")
        except (NoCredentialsError, ClientError) as e:
            logger.warning(f"⚠️  AWS connection failed: {e}. Running in DEMO mode.")
            self._session = None
            self.connected = False
            self.account_id = "DEMO"

    def client(self, service: str, region: str = None):
        """Get a boto3 service client."""
        if not self._session:
            raise RuntimeError("AWS session not initialised – check credentials in .env")
        return self._session.client(service, region_name=region or self.region)

    def resource(self, service: str, region: str = None):
        """Get a boto3 service resource."""
        if not self._session:
            raise RuntimeError("AWS session not initialised – check credentials in .env")
        return self._session.resource(service, region_name=region or self.region)

    def get_all_regions(self) -> list[str]:
        """Return list of all enabled AWS regions."""
        try:
            ec2 = self.client("ec2")
            resp = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
            return [r["RegionName"] for r in resp["Regions"]]
        except Exception:
            return [self.region]


# Singleton instance
aws_client = AWSClient()
