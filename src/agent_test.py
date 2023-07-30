from typing import List
from unittest.mock import Mock
from forta_agent.transaction_event import TransactionEvent
from forta_agent import create_transaction_event
from agent import handle_transaction, PLATFORM_ADDR, ASSET_ADDR, TOPIC_HASH


mock_tx_event: TransactionEvent = create_transaction_event({
    "transaction": {"hash": "0x123"},
    "addresses": {"0x4321": True}
})
mock_tx_event.filter_log = Mock()


class TestFlashLoanDetector:
    def test_returns_empty_list_if_no_aave_contract(self):
        findings: List[TransactionEvent] = handle_transaction(mock_tx_event)
        assert len(findings) == 0

    def test_returns_empty_list_if_no_flash_loan_events(self):
        mock_tx_event.addresses.update({PLATFORM_ADDR: True})
        findings: List[TransactionEvent] = handle_transaction(mock_tx_event)
        assert len(findings) == 0

    def test_returns_finding_in_a_flash_loan(self):
        mock_tx_event.addresses.update({PLATFORM_ADDR: True, ASSET_ADDR: True})
        mock_tx_event.logs = [{
            "topics": [TOPIC_HASH],
            "address": PLATFORM_ADDR
        }]
        findings: List[TransactionEvent] = handle_transaction(mock_tx_event)
        assert len(findings) > 0
