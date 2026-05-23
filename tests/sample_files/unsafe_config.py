# unsafe_config.py
# ⚠️  THIS FILE IS FOR TESTING PURPOSES ONLY.
# These are FAKE secrets used to verify the scanner detects them correctly.
# Never commit real secrets to source control.

import os

# Fake OpenAI key — should be detected as HIGH severity
OPENAI_API_KEY = "sk-fakeOpenAIkey1234567890ABCDEFGtest"

# Fake GitHub token — should be detected as HIGH severity
GITHUB_TOKEN = "ghp_FakeGitHubToken1234567890ABCDE12345"

# Fake AWS credentials — should be detected as HIGH severity
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# Fake hardcoded password — should be detected as HIGH severity
DATABASE_PASSWORD = "password=SuperSecret@123!"

# Fake Stripe live key — should be detected as HIGH severity
STRIPE_SECRET = "sk_live_FakeStripeKey1234567890ABCDEF"

# This is fine — using environment variables
SAFE_KEY = os.environ.get("OPENAI_API_KEY", "")
