from agent.cortensor import CortensorNetwork
from agent.sandbox import DockerSandbox
from agent.x402 import X402Merchant
import time

class AgentCoordinator:
    def __init__(self):
        self.network = CortensorNetwork()
        self.sandbox = DockerSandbox()
        self.merchant = X402Merchant()

        # Ensure Docker is ready
        self.sandbox.build_image()

    def solve_issue(self, issue_url):
        yield "event", "🔍 **Analyzing Issue:** " + issue_url

        # 1. DELEGATE
        yield "event", "📡 **Delegating to Cortensor:** Requesting 3 redundant solutions..."
        candidates = self.network.request_patches(issue_url, redundancy=3)

        # 2. VERIFY
        yield "event", "🛡️ **Starting Verification:** Spinning up Docker Sandbox..."

        mock_test_suite = """
import pytest
from solution import fix_issue
def test_fix():
    assert fix_issue([3,1,2]) == [1,2,3]
    assert fix_issue([]) == []
        """

        verified_winner = None
        logs = []

        for cand in candidates:
            yield "event", f"Testing Patch from **{cand['miner_id']}**..."
            result = self.sandbox.run_verification(cand['code'], mock_test_suite)

            logs.append(f"Miner: {cand['miner_id']}\nResult: {'PASS' if result['success'] else 'FAIL'}\nLogs: {result['logs']}\n---")

            if result['success']:
                verified_winner = cand
                # We don't break immediately; we want to see if others pass too (consensus)

        if not verified_winner:
            yield "error", "❌ No consensus reached. All patches failed verification."
            return

        # 3. MONETIZE (x402)
        yield "event", f"🏆 **Winner Found:** {verified_winner['miner_id']}. Creating x402 Lock..."

        lock_data = self.merchant.create_locked_content(verified_winner['code'])

        final_bundle = {
            "winner": verified_winner['miner_id'],
            "verification_logs": "\n".join(logs),
            "payment_link": lock_data['payment_link'],
            "invoice_id": lock_data['invoice_id']
        }

        yield "complete", final_bundle
