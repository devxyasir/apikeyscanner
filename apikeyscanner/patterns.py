"""
Detection patterns for API keys, tokens, secrets, and credentials.
Each pattern includes a name, regex, severity level, description, and fix suggestion.
"""

from dataclasses import dataclass


@dataclass
class Pattern:
    name: str
    regex: str
    severity: str  # LOW, MEDIUM, HIGH
    description: str
    fix: str


# ──────────────────────────────────────────────
# All detection patterns
# ──────────────────────────────────────────────

PATTERNS: list[Pattern] = [

    # ── AI / ML APIs ──────────────────────────
    Pattern(
        name="OpenAI API Key",
        regex=r"sk-[A-Za-z0-9]{20,}",
        severity="HIGH",
        description="An OpenAI API key was found hardcoded in the source code.",
        fix="Remove the key from code. Store it in an environment variable (OPENAI_API_KEY) and load it with os.environ.get().",
    ),
    Pattern(
        name="OpenAI Organization Key",
        regex=r"org-[A-Za-z0-9]{20,}",
        severity="HIGH",
        description="An OpenAI organization identifier was found in the source code.",
        fix="Store organization IDs in environment variables, not in source code.",
    ),
    Pattern(
        name="Anthropic API Key",
        regex=r"sk-ant-[A-Za-z0-9\-]{20,}",
        severity="HIGH",
        description="An Anthropic Claude API key was found in the source code.",
        fix="Store this key in an environment variable and rotate it immediately.",
    ),
    Pattern(
        name="HuggingFace API Token",
        regex=r"hf_[A-Za-z0-9]{30,}",
        severity="HIGH",
        description="A HuggingFace API token was found in the source code.",
        fix="Store the token in an environment variable (HF_TOKEN) and revoke the exposed token.",
    ),

    # ── Cloud Providers ───────────────────────
    Pattern(
        name="AWS Access Key ID",
        regex=r"(?<![A-Z0-9])(AKIA|AIPA|AIDA|AROA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        severity="HIGH",
        description="An AWS Access Key ID was found in the source code.",
        fix="Rotate this AWS key immediately. Use IAM roles or environment variables instead of hardcoded credentials.",
    ),
    Pattern(
        name="AWS Secret Access Key",
        regex=r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+]{40})['\"]",
        severity="HIGH",
        description="An AWS Secret Access Key was found in the source code.",
        fix="Rotate this AWS secret key immediately and use environment variables or AWS Secrets Manager.",
    ),
    Pattern(
        name="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="HIGH",
        description="A Google API key was found in the source code.",
        fix="Restrict or rotate this Google API key. Store it in an environment variable.",
    ),
    Pattern(
        name="Google OAuth Client Secret",
        regex=r"(?i)google.{0,20}client.{0,20}secret.{0,5}['\"]([A-Za-z0-9\-_]{24,})['\"]",
        severity="HIGH",
        description="A Google OAuth client secret was found in the source code.",
        fix="Rotate the secret in Google Cloud Console and store it securely.",
    ),
    Pattern(
        name="Azure Storage Account Key",
        regex=r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        severity="HIGH",
        description="An Azure Storage Account connection string was found in the source code.",
        fix="Rotate the storage key in Azure Portal and use Azure Key Vault.",
    ),

    # ── Version Control / DevOps ──────────────
    Pattern(
        name="GitHub Personal Access Token",
        regex=r"gh[pousr]_[A-Za-z0-9]{36,}",
        severity="HIGH",
        description="A GitHub personal access token was found in the source code.",
        fix="Revoke this token on GitHub immediately. Use environment variables or GitHub Secrets.",
    ),
    Pattern(
        name="GitHub OAuth Token",
        regex=r"gho_[A-Za-z0-9]{36,}",
        severity="HIGH",
        description="A GitHub OAuth token was found in the source code.",
        fix="Revoke this token on GitHub immediately.",
    ),
    Pattern(
        name="GitLab Personal Access Token",
        regex=r"glpat-[A-Za-z0-9\-]{20,}",
        severity="HIGH",
        description="A GitLab personal access token was found in the source code.",
        fix="Revoke this token in GitLab immediately and store secrets securely.",
    ),

    # ── Payment / Finance ────────────────────
    Pattern(
        name="Stripe Secret Key",
        regex=r"sk_live_[A-Za-z0-9]{24,}",
        severity="HIGH",
        description="A Stripe live secret key was found in the source code.",
        fix="Rotate this Stripe key immediately in the Stripe dashboard. Use environment variables.",
    ),
    Pattern(
        name="Stripe Restricted Key",
        regex=r"rk_live_[A-Za-z0-9]{24,}",
        severity="HIGH",
        description="A Stripe live restricted key was found in the source code.",
        fix="Rotate this Stripe key and store it in an environment variable.",
    ),
    Pattern(
        name="Stripe Test Key",
        regex=r"sk_test_[A-Za-z0-9]{24,}",
        severity="MEDIUM",
        description="A Stripe test secret key was found in the source code.",
        fix="Even test keys should not be hardcoded. Move to environment variables.",
    ),
    Pattern(
        name="PayPal Client Secret",
        regex=r"(?i)paypal.{0,20}secret.{0,5}['\"]([A-Za-z0-9\-_]{20,})['\"]",
        severity="HIGH",
        description="A PayPal client secret was found in the source code.",
        fix="Rotate this PayPal secret immediately.",
    ),

    # ── Messaging / Communication ─────────────
    Pattern(
        name="Slack Bot Token",
        regex=r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
        severity="HIGH",
        description="A Slack bot token was found in the source code.",
        fix="Revoke this Slack token immediately in the Slack API dashboard.",
    ),
    Pattern(
        name="Slack User Token",
        regex=r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
        severity="HIGH",
        description="A Slack user token was found in the source code.",
        fix="Revoke this Slack user token in the Slack API dashboard.",
    ),
    Pattern(
        name="Slack Webhook URL",
        regex=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        severity="MEDIUM",
        description="A Slack webhook URL was found in the source code.",
        fix="Revoke this webhook in Slack and store the URL as an environment variable.",
    ),
    Pattern(
        name="Discord Bot Token",
        regex=r"[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}",
        severity="HIGH",
        description="A Discord bot token was found in the source code.",
        fix="Regenerate this token in the Discord Developer Portal immediately.",
    ),
    Pattern(
        name="Telegram Bot Token",
        regex=r"[0-9]{8,10}:[A-Za-z0-9\-_]{35,}",
        severity="HIGH",
        description="A Telegram bot token was found in the source code.",
        fix="Revoke and regenerate the token using BotFather.",
    ),
    Pattern(
        name="Twilio Account SID",
        regex=r"AC[a-z0-9]{32}",
        severity="MEDIUM",
        description="A Twilio Account SID was found in the source code.",
        fix="Store this in an environment variable. Also check for any associated auth tokens.",
    ),
    Pattern(
        name="Twilio Auth Token",
        regex=r"(?i)twilio.{0,20}auth.{0,10}token.{0,5}['\"]([a-z0-9]{32})['\"]",
        severity="HIGH",
        description="A Twilio Auth Token was found in the source code.",
        fix="Rotate this token in the Twilio Console immediately.",
    ),
    Pattern(
        name="SendGrid API Key",
        regex=r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        severity="HIGH",
        description="A SendGrid API key was found in the source code.",
        fix="Revoke this key in the SendGrid dashboard and store it as an environment variable.",
    ),
    Pattern(
        name="Mailgun API Key",
        regex=r"key-[A-Za-z0-9]{32}",
        severity="HIGH",
        description="A Mailgun API key was found in the source code.",
        fix="Revoke this key in the Mailgun dashboard and store it securely.",
    ),

    # ── Authentication / Tokens ───────────────
    Pattern(
        name="JWT Token",
        regex=r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        severity="MEDIUM",
        description="A JSON Web Token (JWT) was found in the source code.",
        fix="Do not hardcode JWTs. Generate them at runtime and store secrets used to sign JWTs in environment variables.",
    ),
    Pattern(
        name="Bearer Token",
        regex=r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",
        severity="MEDIUM",
        description="A Bearer token was found hardcoded in the source code.",
        fix="Never hardcode Bearer tokens. Retrieve them dynamically at runtime.",
    ),
    Pattern(
        name="Basic Auth Credentials",
        regex=r"(?i)https?://[A-Za-z0-9._~-]+:[A-Za-z0-9._~!$&'()*+,;=%@-]+@",
        severity="HIGH",
        description="Credentials were found embedded in a URL.",
        fix="Never embed credentials in URLs. Use environment variables or a secrets manager.",
    ),

    # ── Private Keys / Certificates ───────────
    Pattern(
        name="RSA Private Key",
        regex=r"-----BEGIN RSA PRIVATE KEY-----",
        severity="HIGH",
        description="An RSA private key block was found in the source code.",
        fix="Remove this private key from source code immediately. Store it in a secure key vault or secrets manager.",
    ),
    Pattern(
        name="Generic Private Key",
        regex=r"-----BEGIN PRIVATE KEY-----",
        severity="HIGH",
        description="A private key block was found in the source code.",
        fix="Remove this private key from source code immediately.",
    ),
    Pattern(
        name="EC Private Key",
        regex=r"-----BEGIN EC PRIVATE KEY-----",
        severity="HIGH",
        description="An EC (Elliptic Curve) private key block was found in the source code.",
        fix="Remove this private key from source code immediately.",
    ),
    Pattern(
        name="OpenSSH Private Key",
        regex=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity="HIGH",
        description="An OpenSSH private key was found in the source code.",
        fix="Remove this key immediately. Generate a new key pair and store privately.",
    ),
    Pattern(
        name="PGP Private Key Block",
        regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="HIGH",
        description="A PGP private key block was found in the source code.",
        fix="Remove this key block immediately and revoke the compromised key.",
    ),

    # ── Databases ─────────────────────────────
    Pattern(
        name="Database URL",
        regex=r"(?i)(database_url|db_url)\s*=\s*['\"]?(postgres|mysql|mongodb|sqlite|redis|mssql)[^\s'\"]+",
        severity="HIGH",
        description="A database connection URL with embedded credentials was found.",
        fix="Store database URLs in environment variables. Never commit connection strings with passwords.",
    ),
    Pattern(
        name="MongoDB Connection String",
        regex=r"mongodb(\+srv)?://[A-Za-z0-9._~-]+:[A-Za-z0-9._~!$&'()*+,;=%@-]+@",
        severity="HIGH",
        description="A MongoDB connection string with credentials was found in the source code.",
        fix="Move this connection string to an environment variable and rotate the database password.",
    ),
    Pattern(
        name="PostgreSQL Connection String",
        regex=r"postgres(ql)?://[A-Za-z0-9._~-]+:[A-Za-z0-9._~!$&'()*+,;=%@-]+@",
        severity="HIGH",
        description="A PostgreSQL connection string with credentials was found in the source code.",
        fix="Move this connection string to an environment variable and rotate the database password.",
    ),
    Pattern(
        name="MySQL Connection String",
        regex=r"mysql://[A-Za-z0-9._~-]+:[A-Za-z0-9._~!$&'()*+,;=%@-]+@",
        severity="HIGH",
        description="A MySQL connection string with credentials was found in the source code.",
        fix="Move this connection string to an environment variable and rotate the database password.",
    ),
    Pattern(
        name="Redis URL",
        regex=r"redis://:[A-Za-z0-9._~!$&'()*+,;=%@-]+@",
        severity="MEDIUM",
        description="A Redis URL with a password was found in the source code.",
        fix="Store the Redis URL in an environment variable.",
    ),

    # ── Hardcoded Secrets / Passwords ─────────
    Pattern(
        name="Hardcoded Password",
        regex=r"(?i)(password|passwd|pwd)\s*=\s*['\"][A-Za-z0-9!@#$%^&*()\-_+=<>?]{6,}['\"]",
        severity="HIGH",
        description="A hardcoded password was found in the source code.",
        fix="Never hardcode passwords. Use environment variables or a secrets manager.",
    ),
    Pattern(
        name="Hardcoded Secret",
        regex=r"(?i)(secret|secret_key|app_secret)\s*=\s*['\"][A-Za-z0-9!@#$%^&*()\-_+=<>?]{8,}['\"]",
        severity="HIGH",
        description="A hardcoded secret or secret key was found in the source code.",
        fix="Move this value to an environment variable immediately.",
    ),
    Pattern(
        name="Hardcoded Token",
        regex=r"(?i)(token|api_token|access_token|auth_token)\s*=\s*['\"][A-Za-z0-9\-_\.]{16,}['\"]",
        severity="MEDIUM",
        description="A hardcoded token was found in the source code.",
        fix="Store tokens in environment variables. Never commit them to source control.",
    ),
    Pattern(
        name="Hardcoded API Key",
        regex=r"(?i)(api_key|apikey|api-key)\s*=\s*['\"][A-Za-z0-9\-_\.]{16,}['\"]",
        severity="HIGH",
        description="A hardcoded API key was found in the source code.",
        fix="Move the API key to an environment variable immediately.",
    ),
    Pattern(
        name="Generic Secret Assignment",
        regex=r"(?i)(private_key|secret_token|encryption_key)\s*=\s*['\"][A-Za-z0-9+/=\-_]{16,}['\"]",
        severity="HIGH",
        description="A generic hardcoded cryptographic key or secret was found.",
        fix="Remove this value and store it in a secrets manager or environment variable.",
    ),

    # ── .env File Values ──────────────────────
    Pattern(
        name=".env Sensitive Value",
        regex=r"(?i)^(SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL|AUTH|API_KEY|PRIVATE)[A-Z_]*\s*=\s*.{8,}",
        severity="MEDIUM",
        description="A sensitive value was found in a .env file.",
        fix="Ensure this .env file is in .gitignore and never committed to source control.",
    ),

    # ── Infrastructure / DevOps ───────────────
    Pattern(
        name="NPM Auth Token",
        regex=r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-]{36,}",
        severity="HIGH",
        description="An NPM registry auth token was found in the source code.",
        fix="Remove this token from .npmrc and use NPM_TOKEN as an environment variable.",
    ),
    Pattern(
        name="Docker Registry Password",
        regex=r"(?i)docker.{0,20}password.{0,5}['\"]([A-Za-z0-9!@#$%^&*\-_+=]{8,})['\"]",
        severity="HIGH",
        description="A Docker registry password was found in the source code.",
        fix="Use Docker secrets or environment variables for registry credentials.",
    ),
    Pattern(
        name="SSH Private Key Path with Passphrase",
        regex=r"(?i)passphrase\s*=\s*['\"][A-Za-z0-9!@#$%^&*\-_+=]{6,}['\"]",
        severity="MEDIUM",
        description="An SSH key passphrase was found hardcoded in the source code.",
        fix="Do not hardcode SSH passphrases. Use SSH agents or secret managers.",
    ),
    Pattern(
        name="Firebase API Key",
        regex=r"(?i)firebase.{0,30}['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
        severity="HIGH",
        description="A Firebase API key was found in the source code.",
        fix="Restrict this key in the Firebase Console and store it as an environment variable.",
    ),
    Pattern(
        name="Heroku API Key",
        regex=r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        severity="HIGH",
        description="A Heroku API key was found in the source code.",
        fix="Revoke this key in the Heroku dashboard and store it as an environment variable.",
    ),
    Pattern(
        name="DigitalOcean Personal Access Token",
        regex=r"dop_v1_[A-Za-z0-9]{64}",
        severity="HIGH",
        description="A DigitalOcean personal access token was found.",
        fix="Revoke this token in the DigitalOcean API settings immediately.",
    ),
    Pattern(
        name="Vercel Token",
        regex=r"(?i)vercel.{0,20}['\"]([A-Za-z0-9]{24,})['\"]",
        severity="MEDIUM",
        description="A possible Vercel token was found in the source code.",
        fix="Store Vercel tokens as environment variables and never commit them.",
    ),
]
