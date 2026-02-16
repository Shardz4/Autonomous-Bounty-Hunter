import uuid
import time
import os
from dotenv import load_dotenv

load_dotenv()

class X402Merchant:
    def __init__(self):
        # In production, this would connect to an L402/Lightning node
        self.active_invoices = {}
        # Load x402 gateway URL from environment, with fallback
        self.gateway_url = os.getenv(
            "X402_GATEWAY_URL", 
            "https://x402.pay/invoice"  # Real x402 service or your local gateway
        )

    def create_locked_content(self, content, price_usdc=5.00):
        """
        Gates content behind a payment request.
        """
        invoice_id = str(uuid.uuid4())[:8]
        payment_link = f"{self.gateway_url}/{invoice_id}?amount={price_usdc}"

        # Store the content securely
        self.active_invoices[invoice_id] = {
            "content": content,
            "status": "unpaid",
            "price": price_usdc,
            "created_at": time.time()
        }

        return {
            "invoice_id": invoice_id,
            "payment_link": payment_link,
            "status": "402 Payment Required"
        }

    def verify_payment(self, invoice_id):
        """
        Checks if the invoice has been paid.
        (Mocked to auto-succeed for Demo purposes after 5 seconds)
        """
        if invoice_id not in self.active_invoices:
            return None

        # 🟢 SIMULATION: Auto-mark as paid for the demo
        self.active_invoices[invoice_id]['status'] = "paid"

        return self.active_invoices[invoice_id]['status'] == "paid"

    def retrieve_content(self, invoice_id):
        """
        Returns content ONLY if paid.
        """
        invoice = self.active_invoices.get(invoice_id)
        if invoice and invoice['status'] == 'paid':
            return invoice['content']
        raise PermissionError("402 Payment Required: Content is locked.")
