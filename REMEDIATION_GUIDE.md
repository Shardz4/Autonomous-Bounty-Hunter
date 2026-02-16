# 🛠️ REMEDIATION GUIDE - Security Fixes

## Quick Fixes by Priority

### PRIORITY 1: CRITICAL (Fix Immediately)

---

## FIX CVE-001: Add Code Validation

**File:** `agent/sandbox.py`

```python
import ast

def validate_patch(code):
    """
    Validates Python code before execution.
    Prevents execution of dangerous imports/functions.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        raise ValueError(f"Invalid Python syntax: {e}")

    # Define forbidden imports and functions
    forbidden_modules = {'socket', 'subprocess', 'os.system', 'eval', 'exec', '__import__', 'open'}
    forbidden_functions = {'eval', 'exec', '__import__', 'compile', 'input', 'breakpoint'}

    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_modules:
                    raise ValueError(f"Forbidden import: {alias.name}")

        if isinstance(node, ast.ImportFrom):
            if node.module in forbidden_modules:
                raise ValueError(f"Forbidden import: {node.module}")

        # Check function calls
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in forbidden_functions:
                    raise ValueError(f"Forbidden function: {node.func.id}")

    return True


# Update run_verification to use validation:

def run_verification(self, code_patch, test_code):
    """
    Spins up a container, validates code, injects it, runs tests.
    """
    try:
        # 🛡️ SECURITY: Validate before execution
        validate_patch(code_patch)
        validate_patch(test_code)

        # Create container
        container = self.client.containers.run(
            self.image_tag,
            command="python -m pytest test_suite.py",
            detach=True,
            network_mode="none",
            mem_limit="128m",
            memswap_limit="128m",
            cap_drop=['ALL'],
            read_only=True,
            tmpfs={'/tmp': 'size=64M'},
        )

        # Inject code
        self._copy_to_container(container, "solution.py", code_patch)
        self._copy_to_container(container, "test_suite.py", test_code)

        # Wait and cleanup
        result = container.wait()
        logs = container.logs().decode('utf-8')
        container.remove()

        return {"success": result['StatusCode'] == 0, "logs": logs}

    except ValueError as e:
        # Code validation failed - security issue!
        logger.warning(f"Code validation failed: {e}")
        return {"success": False, "logs": f"Code validation failed: {str(e)}"}
    except Exception as e:
        logger.error(f"Container error: {e}")
        return {"success": False, "logs": str(e)}
```

---

## FIX CVE-002: Proper URL Validation

**File:** `app.py`

```python
import re
from urllib.parse import urlparse

def validate_github_issue_url(url):
    """
    Validates GitHub issue URL format and structure.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")

    # Check protocol
    if not url.startswith("https://github.com/"):
        raise ValueError("URL must be HTTPS GitHub URL")

    # Strict regex for GitHub issue URLs
    # Format: https://github.com/owner/repo/issues/number
    pattern = r'^https://github\.com/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-\.]+/issues/\d+/?$'

    if not re.match(pattern, url):
        raise ValueError(
            "Invalid URL format. Expected: "
            "https://github.com/owner/repo/issues/number"
        )

    # Parse and verify hostname
    parsed = urlparse(url)
    if parsed.hostname != 'github.com':
        raise ValueError("Only github.com domain allowed")

    # Check for path traversal attempts
    path = parsed.path
    if '..' in path or '%' in path or '\x00' in path:
        raise ValueError("URL contains suspicious characters")

    return True


# Update app.py button handler:

if run_btn:
    try:
        validate_github_issue_url(issue_url)  # Add validation!
    except ValueError as e:
        st.error(f"❌ Invalid GitHub URL: {e}")
        st.stop()

    try:
        agent = AgentCoordinator()
    except RuntimeError as e:
        logger.error(f"Agent init failed: {str(e)}")
        st.error("❌ Failed to initialize agent. Please contact support.")
        st.stop()

    # ... rest of code
```

---

## FIX CVE-003: Real Payment Verification

**File:** `agent/x402.py`

```python
import uuid
import time
import os
import requests
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv()

class X402Merchant:
    def __init__(self):
        self.active_invoices = {}
        self.gateway_url = os.getenv(
            "X402_GATEWAY_URL",
            "https://x402.pay/invoice"
        )
        # 🛡️ SECURITY: Store API key securely
        self.api_key = os.getenv("X402_API_KEY")
        if not self.api_key:
            logger.warning("X402_API_KEY not set - payment verification will fail")

    def create_locked_content(self, content, price_usdc=5.00):
        """Gates content behind a payment request."""
        # Use FULL UUID (not truncated!)
        invoice_id = str(uuid.uuid4())

        payment_link = f"{self.gateway_url}/{invoice_id}?amount={price_usdc}"

        self.active_invoices[invoice_id] = {
            "content": content,
            "status": "unpaid",
            "price": price_usdc,
            "created_at": time.time(),
            "access_attempts": 0,
            "failed_attempts": 0,
        }

        logger.info(f"Invoice created: {invoice_id}, Price: {price_usdc} USDC")

        return {
            "invoice_id": invoice_id,
            "payment_link": payment_link,
            "status": "402 Payment Required"
        }

    def verify_payment(self, invoice_id):
        """
        🛡️ SECURITY: Verify payment against REAL x402 service.
        Does NOT auto-approve.
        """
        if invoice_id not in self.active_invoices:
            logger.warning(f"Invoice not found: {invoice_id}")
            return False

        try:
            # Call REAL x402 API
            response = requests.get(
                f"{self.gateway_url}/verify/{invoice_id}",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "User-Agent": "Cortensor/1.0"
                },
                timeout=5
            )

            response.raise_for_status()

            payment_data = response.json()

            # Only mark as paid if API confirms it
            if payment_data.get('status') == 'paid':
                self.active_invoices[invoice_id]['status'] = 'paid'
                logger.info(f"Payment verified: {invoice_id}")
                return True

            return False

        except requests.exceptions.RequestException as e:
            # FAIL CLOSED on network error
            logger.error(f"Payment verification failed for {invoice_id}: {e}")
            return False
        except ValueError as e:
            logger.error(f"Invalid payment response: {e}")
            return False

    def retrieve_content(self, invoice_id):
        """Returns content ONLY if verified as paid."""
        invoice = self.active_invoices.get(invoice_id)

        if not invoice:
            raise PermissionError("402 Payment Required: Invoice not found.")

        if invoice['status'] != 'paid':
            invoice['failed_attempts'] += 1

            # Rate limit access attempts
            if invoice['failed_attempts'] > 10:
                logger.warning(f"Too many failed attempts for {invoice_id}")
                raise PermissionError(
                    "402 Payment Required: Too many failed attempts."
                )

            raise PermissionError("402 Payment Required: Content is locked.")

        logger.info(f"Content retrieved for {invoice_id}")
        return invoice['content']

    def cleanup_expired_invoices(self, max_age_seconds=86400):  # 24 hours
        """Remove old invoices to prevent memory leak."""
        current_time = time.time()
        expired = [
            inv_id for inv_id, inv_data in self.active_invoices.items()
            if current_time - inv_data['created_at'] > max_age_seconds
        ]

        for inv_id in expired:
            del self.active_invoices[inv_id]
            logger.info(f"Cleaned up expired invoice: {inv_id}")

        return len(expired)
```

**Add to `.env.example`:**
```ini
# x402 Payment Gateway
X402_GATEWAY_URL=https://x402.pay/invoice
X402_API_KEY=your_api_key_here
```

---

## FIX CVE-004: Cryptographic Signatures

**File:** `agent/cortensor.py`

```python
import hashlib
import hmac
import logging

logger = logging.getLogger(__name__)

class CortensorNetwork:
    def __init__(self, miner_secret_keys=None):
        self.miners = [
            {"id": "Miner_Alpha", "model": "Llama-3-70b", "secret": "alpha_secret_key"},
            {"id": "Miner_Beta", "model": "Mistral-Large", "secret": "beta_secret_key"},
            {"id": "Miner_Gamma", "model": "GPT-4-Turbo", "secret": "gamma_secret_key"},
            {"id": "Miner_Delta", "model": "Claude-3-Opus", "secret": "delta_secret_key"}
        ]

    def _generate_signature(self, code, miner_secret):
        """
        🛡️ SECURITY: Generate cryptographic signature using HMAC-SHA256.
        Replaces weak random signature generation.
        """
        # Hash the code
        code_hash = hashlib.sha256(code.encode()).digest()

        # Sign with miner's secret key
        signature = hmac.new(
            miner_secret.encode(),
            code_hash,
            hashlib.sha256
        ).hexdigest()

        return signature

    def _verify_signature(self, code, signature, miner_secret):
        """Verify a patch signature."""
        expected_sig = self._generate_signature(code, miner_secret)
        return hmac.compare_digest(signature, expected_sig)

    def request_patches(self, issue_description, redundancy=3):
        """
        Simulates sending a prompt to 'n' different miners.
        Returns signed, cryptographically-secured patches.
        """
        if redundancy < 1 or redundancy > len(self.miners):
            redundancy = min(redundancy, len(self.miners))

        import random
        selected_miners = random.sample(self.miners, redundancy)
        results = []

        logger.info(f"Broadcasting task to {len(selected_miners)} miners")

        for miner in selected_miners:
            try:
                import time
                time.sleep(0.5)  # Simulate network latency

                # Generate patch code
                patch_code = f"""
def fix_issue(data):
    # Fixed by {miner['id']} using {miner['model']}
    if not data:
        return []
    return sorted(data)
                """

                # 🛡️ SECURITY: Sign with cryptographic key
                signature = self._generate_signature(patch_code, miner['secret'])

                results.append({
                    "miner_id": miner['id'],
                    "code": patch_code,
                    "signature": signature,  # Cryptographically signed!
                    "model": miner['model']
                })

                logger.info(f"Received patch from {miner['id']} ({miner['model']})")

            except Exception as e:
                logger.error(f"Error getting patch from {miner['id']}: {str(e)}")
                continue

        return results
```

---

## FIX CVE-005: Full UUID Invoice IDs

**File:** `agent/x402.py` (already shown above)

```python
# BEFORE (vulnerable):
invoice_id = str(uuid.uuid4())[:8]  # Only 8 chars!

# AFTER (secure):
invoice_id = str(uuid.uuid4())  # Full UUID (36 chars, 128-bit entropy)
```

**Impact:**
- Before: 16^8 = 4.3 billion combinations (brute-forceable in seconds)
- After: 16^36 = 10^43 combinations (impossible to brute force)

---

### PRIORITY 2: HIGH SEVERITY

---

## FIX CVE-006: Add Rate Limiting

**File:** New file `agent/rate_limiter.py`

```python
import time
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, identifier):
        """Check if request is allowed for identifier."""
        now = time.time()

        # Clean old requests outside window
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if now - req_time < self.window_seconds
        ]

        # Check limit
        if len(self.requests[identifier]) < self.max_requests:
            self.requests[identifier].append(now)
            return True

        logger.warning(f"Rate limit exceeded for {identifier}")
        return False

    def get_reset_time(self, identifier):
        """Get when rate limit resets (seconds)."""
        if not self.requests[identifier]:
            return 0

        oldest = min(self.requests[identifier])
        return self.window_seconds - (time.time() - oldest)
```

**File:** `app.py` - Add rate limiting to Streamlit app

```python
from agent.rate_limiter import RateLimiter

# Initialize rate limiter
rate_limiter = RateLimiter(max_requests=5, window_seconds=300)  # 5 per 5 minutes

if run_btn:
    # Check rate limit
    user_ip = st.session_state.get("user_ip", "unknown")
    if not rate_limiter.is_allowed(user_ip):
        reset_time = rate_limiter.get_reset_time(user_ip)
        st.error(f"❌ Rate limit exceeded. Try again in {reset_time:.0f} seconds.")
        st.stop()

    # ... rest of code
```

---

## FIX CVE-007: Secure Error Handling

**File:** `app.py`

```python
import logging

logger = logging.getLogger(__name__)

# BEFORE (vulnerable):
except RuntimeError as e:
    st.error(f"❌ Failed to initialize agent: {str(e)}")  # Exposes internals!

# AFTER (secure):
except RuntimeError as e:
    logger.error(f"Agent initialization failed: {str(e)}")  # Log internally
    st.error("❌ Failed to initialize agent. Please contact support.")  # Generic message

# BEFORE (vulnerable):
except Exception as e:
    return {"success": False, "logs": str(e)}  # All Docker errors exposed!

# AFTER (secure):
except Exception as e:
    logger.error(f"Verification failed: {str(e)}", exc_info=True)
    return {"success": False, "logs": "Verification failed"}  # Generic message
```

---

## FIX CVE-008: Fetch Real GitHub Tests

**File:** `agent/coordinator.py`

```python
import requests
import logging
import base64

logger = logging.getLogger(__name__)

class AgentCoordinator:
    # ... existing code ...

    def _fetch_github_tests(self, issue_url):
        """
        Fetch actual test files from GitHub repository.
        Parses: https://github.com/owner/repo/issues/123
        """
        try:
            # Parse URL
            parts = issue_url.strip('/').split('/')
            owner = parts[-4]
            repo = parts[-3]

            # Try common test file locations
            test_files = [
                'tests/test_fix.py',
                'test.py',
                'tests/test_main.py',
                'tests/test_solution.py'
            ]

            for test_file in test_files:
                try:
                    response = requests.get(
                        f"https://api.github.com/repos/{owner}/{repo}/contents/{test_file}",
                        timeout=5,
                        headers={"Accept": "application/vnd.github.v3.raw"}
                    )

                    if response.status_code == 200:
                        logger.info(f"Found test file: {test_file}")
                        return response.text

                except Exception as e:
                    logger.debug(f"Test file not found: {test_file}")
                    continue

            # If no test found, return safe default
            logger.warning(f"No test file found for {owner}/{repo}")
            return self._default_test_template()

        except Exception as e:
            logger.error(f"Failed to fetch tests: {e}")
            return self._default_test_template()

    def _default_test_template(self):
        """Safe default test template."""
        return """
import pytest

def test_solution_exists():
    \"\"\"Verify solution module exists.\"\"\"
    from solution import fix_issue
    assert callable(fix_issue)

def test_basic():
    \"\"\"Basic sanity test.\"\"\"
    from solution import fix_issue
    # This test will fail if solution has syntax errors
    result = fix_issue([3, 1, 2])
    assert isinstance(result, (list, tuple))
"""

    def solve_issue(self, issue_url):
        # ... delegation code ...

        # 🛡️ SECURITY: Fetch REAL tests instead of mocking
        test_suite = self._fetch_github_tests(issue_url)

        # ... rest of code ...
```

---

## FIX CVE-009: Enhanced Docker Security

**File:** `agent/sandbox.py`

```python
def run_verification(self, code_patch, test_code):
    """
    Spins up a container with comprehensive security hardening.
    """
    try:
        # Validate code first
        validate_patch(code_patch)
        validate_patch(test_code)

        # 🛡️ SECURITY: Comprehensive container hardening
        container = self.client.containers.run(
            self.image_tag,
            command="python -m pytest test_suite.py",
            detach=True,

            # Network security
            network_mode="none",
            ipc_mode="private",

            # Resource limits
            mem_limit="128m",
            memswap_limit="128m",
            cpu_count=1,
            cpu_period=100000,
            cpu_quota=10000,  # 10% CPU
            pids_limit=10,    # Max 10 processes

            # Filesystem security
            read_only=True,

            # Temporary filesystem
            tmpfs={
                '/tmp': 'size=64M,mode=1777',
                '/app': 'size=512M',
            },

            # Capability dropping
            cap_drop=['ALL'],
            cap_add=['CHOWN', 'SETUID'],  # Only if needed

            # Security options
            security_opt=[
                'no-new-privileges:true',
                'apparmor=docker-default'  # If available
            ],

            # Resource limits
            ulimits=[
                docker.types.Ulimit(name='nofile', soft=1024, hard=1024),
                docker.types.Ulimit(name='nproc', soft=5, hard=5),
                docker.types.Ulimit(name='fsize', soft=10485760, hard=10485760),  # 10MB max file
            ]
        )

        # Inject and run
        self._copy_to_container(container, "solution.py", code_patch)
        self._copy_to_container(container, "test_suite.py", test_code)

        # Wait with timeout
        try:
            result = container.wait(timeout=30)
        except:
            container.kill()
            return {"success": False, "logs": "Execution timeout"}

        logs = container.logs().decode('utf-8')
        container.remove()

        return {"success": result['StatusCode'] == 0, "logs": logs}

    except ValueError as e:
        logger.warning(f"Code validation failed: {e}")
        return {"success": False, "logs": f"Validation error"}
    except Exception as e:
        logger.error(f"Container error: {e}")
        return {"success": False, "logs": "Execution error"}
```

---

### PRIORITY 3: MEDIUM SEVERITY

---

## FIX CVE-011: Persistent Storage

Use SQLite or Redis instead of in-memory dictionary.

## FIX CVE-012: Add CSRF Tokens

Implement token validation for payment actions.

## FIX CVE-013: Pin Dependencies

```txt
# BEFORE (vulnerable):
streamlit>=1.28.0

# AFTER (secure):
streamlit==1.28.1
docker==6.1.0
requests==2.31.0
python-dotenv==1.0.0
pytest==7.4.0
```

---

## Testing the Fixes

```bash
# Install dependencies
pip install -r requirements.txt

# Run security validation tests
python -m pytest tests/security_tests.py -v

# Run code validation
python -c "from agent.sandbox import validate_patch; validate_patch('print(1)')"

# Performance testing
python tests/performance_tests.py
```

---

## Deployment Checklist

- [ ] All CRITICAL vulnerabilities fixed
- [ ] Code validation tests pass
- [ ] Payment verification tested with real API
- [ ] Docker security hardening verified
- [ ] Rate limiting tested
- [ ] Error messages don't leak info
- [ ] Dependencies pinned and audited
- [ ] Audit logging implemented
- [ ] Security review completed
- [ ] Penetration testing passed

---

*Last Updated: 2026-02-16*
