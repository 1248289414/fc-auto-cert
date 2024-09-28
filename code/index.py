import subprocess
import logging
import os
import datetime

import oss2

from cas.index import get_cert_by_id

import certbot.main

CERTBOT_DIR = "/tmp/certbot"
CERTBOT_SERVER = "https://acme-v02.api.letsencrypt.org/directory"


def check_if_less_than_31_days(x):
    d = datetime.datetime.strptime(x, "%Y-%m-%d")
    now = datetime.datetime.now()
    return (d - now).days < 31


def create_credentials_ini_file():
    if not os.path.exists(CERTBOT_DIR):
        os.makedirs(CERTBOT_DIR)
    with open(os.path.join(CERTBOT_DIR, "credentials.ini"), "w") as f:
        f.write("dns_multi_provider = alidns\n")
        f.write("ALICLOUD_ACCESS_KEY = " + os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"] + "\n")
        f.write("ALICLOUD_SECRET_KEY = " + os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"] + "\n")
        f.write("ALICLOUD_SECURITY_TOKEN = " + os.environ["ALIBABA_CLOUD_SECURITY_TOKEN"] + "\n")


def obtain_cert(domain_name):
    certbot_args = [
        "--config-dir",
        CERTBOT_DIR,
        "--work-dir",
        CERTBOT_DIR,
        "--logs-dir",
        CERTBOT_DIR,
        # Obtain a cert but don't install it
        "certonly",
        # Run in non-interactive mode
        "--quiet",
        "--non-interactive",
        # Agree to the terms of service
        "--agree-tos",
        "--cert-name",
        domain_name,
        # Email of domain administrators
        "--email",
        os.environ["EMAIL"],
        # Use the dns challenge with alidns
        "--authenticator",
        "dns-multi",
        "--dns-multi-credentials",
        str(os.path.join(CERTBOT_DIR, "credentials.ini")),
        "--preferred-challenges",
        "dns",
        "--dns-multi-propagation-seconds",
        "30",
        "--key-type",
        "rsa",
        # Use this server instead of default acme-v01
        "--server",
        CERTBOT_SERVER,
        # Domains to provision certs for (comma separated)
        "--domains",
        domain_name,
    ]
    return certbot.main.main(certbot_args)

def read_cert(cert_dir):
    with open(os.path.join(cert_dir, "fullchain.pem")) as f:
        fullchain = f.read()
    with open(os.path.join(cert_dir, "privkey.pem")) as f:
        privkey = f.read()
    return fullchain, privkey

def update_cert(bucket, domain, certificate, private_key):
    cert = oss2.models.CertInfo(certificate=certificate, private_key=private_key, force=True)
    request = oss2.models.PutBucketCnameRequest(domain, cert)
    return bucket.put_bucket_cname(request)


def handler(event, context):
    logger = logging.getLogger()

    try:
        # get environment variable BucketName
        bucket_name = os.environ["BUCKNAME"]
        # get environment variable Endpoint
        endpoint = os.environ["ENDPOINT"]
    except KeyError as e:
        logger.error("Please set BUCKNAME and ENDPOINT environment variables")
        raise e

    logger.info(f"Endpoint: {endpoint}")
    logger.info(f"BucketName: {bucket_name}")

    create_credentials_ini_file()

    auth = oss2.ProviderAuth(
        oss2.credentials.StaticCredentialsProvider(
            access_key_id=os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"],
            access_key_secret=os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
            security_token=os.environ["ALIBABA_CLOUD_SECURITY_TOKEN"],
        )
    )

    bucket = oss2.Bucket(auth, endpoint, bucket_name)
    bucket_cname = bucket.list_bucket_cname()

    for c in bucket_cname.cname:
        domain = c.domain
        logger.info(f"Check CNAME: {domain} start.")

        if c.status != "Enabled":
            logger.warn(f"CNAME {domain} is not enabled.")
            continue

        need_obtain_cert = False
        if c.certificate is not None:
            logger.info(f"CNAME {domain} certificate is enabled.")
            CertId = str.split(c.certificate.cert_id, "-")[0]
            cert = get_cert_by_id(CertId)

            if not check_if_less_than_31_days(cert.end_date):
                logger.info(f"CNAME {domain} certificate is not expired.")
                need_obtain_cert = False
            else:
                logger.info(f"CNAME {domain} certificate will expire in 30 days, we will renew it.")
                need_obtain_cert = True
        else:
            logger.info(f"CNAME {domain} certificate is not enabled, we will enable it.")
            need_obtain_cert = True

        if need_obtain_cert:
            logger.info(f"Beging to obtain cert for {domain}")
            obtain_cert(domain)

            if not os.path.exists(os.path.join(CERTBOT_DIR, "live", domain)):
                logger.error(f"Obtain cert for {domain} failed.")
                continue
            else:
                logger.info(f"Obtain cert for {domain} done.")

            fullchain, privkey = read_cert(os.path.join(CERTBOT_DIR, "live", domain))
            update_cert(bucket, domain, fullchain, privkey)

        logger.info(f"Check CNAME: {domain} done.")

    return event
