import streamlit as st
from agent.coordinator import AgentCoordinator
import time

st.set_page_config(page_title="Cortensor Bounty Hunter", page_icon="🤖", layout="wide")

# Custom CSS for x402 styling
st.markdown("""
<style>
    .stSuccess { border-left: 5px solid #00ff00; }
    .payment-box {
        padding: 20px;
        border-radius: 10px;
        background-color: #f0f2f6;
        border: 1px solid #d1d5db;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

st.title("🤖 Autonomous Bounty Hunter")
st.markdown("### Delegate. Execute. Verify. Monetize.")

with st.sidebar:
    st.header("Agent Status")
    st.markdown("🟢 **Cortensor Network:** Connected")
    st.markdown("🟢 **Docker Sandbox:** Ready")
    st.markdown("🟠 **x402 Gateway:** Active (Testnet)")
    st.divider()
    st.info("This agent autonomously delegates coding tasks to the Cortensor network, verifies them in a sandbox, and sells the fix via x402.")

# Input
issue_url = st.text_input("Enter GitHub Issue URL", "https://github.com/cortensor/protocol/issues/101")
run_btn = st.button("🔫 Start Bounty Hunt", type="primary")

if run_btn:
    # Validate URL
    if not issue_url or not issue_url.startswith("https://github.com/"):
        st.error("❌ Please enter a valid GitHub issue URL (must start with https://github.com/)")
        st.stop()
    
    try:
        agent = AgentCoordinator()
    except RuntimeError as e:
        st.error(f"❌ Failed to initialize agent: {str(e)}")
        st.stop()

    # UI Containers
    status_box = st.empty()
    log_box = st.expander("Runtime Logs", expanded=True)
    result_box = st.container()

    logs = []

    # Run the Generator
    for msg_type, data in agent.solve_issue(issue_url):
        if msg_type == "event":
            status_box.info(data)
            logs.append(f"[{time.strftime('%H:%M:%S')}] {data}")
            log_box.text("\n".join(logs))

        elif msg_type == "error":
            status_box.error(data)

        elif msg_type == "complete":
            status_box.success("✅ Workflow Complete!")

            with result_box:
                st.divider()
                c1, c2 = st.columns([1, 1])

                with c1:
                    st.subheader("📜 Verification Certificate")
                    st.code(data['verification_logs'], language="text")
                    st.caption(f"Winner: {data['winner']}")

                with c2:
                    st.subheader("💰 x402 Payment Gate")
                    st.markdown(f"""
                    <div class="payment-box">
                        <h3>Payment Required</h3>
                        <p>To unlock the source code, please settle the invoice.</p>
                        <h1>5.00 USDC</h1>
                        <small>Invoice ID: {data['invoice_id']}</small>
                    </div>
                    """, unsafe_allow_html=True)
                    st.link_button("🔗 Pay via x402", data['payment_link'], use_container_width=True)
