import os
import sys
from typing import List
from dotenv import load_dotenv
from forta_agent import Finding, FindingType, FindingSeverity
from forta_agent.transaction_event import TransactionEvent

load_dotenv()

try:
    PLATFORM_ADDR = os.environ.get("PLATFORM_ADDR").lower()
    ASSET_ADDR = os.environ.get("ASSET_ADDR").lower()
    TOPIC_HASH = os.environ.get("TOPIC_HASH").lower()
except:
    print("Confirm if all the required variables are provided.")
    sys.exit(1)


def handle_transaction(transaction_event: TransactionEvent) -> List[TransactionEvent]:
    findings: List[TransactionEvent] = []

    addresses = list(map(lambda address: address.lower(),
                         transaction_event.addresses.keys()))

    if PLATFORM_ADDR not in addresses:
        return findings

    flash_loan_events = filter(lambda log: any(filter(
        lambda topic: topic.lower() == TOPIC_HASH, log["topics"])), transaction_event.logs)

    if not next(flash_loan_events, False):
        return findings

    if ASSET_ADDR in addresses:
        findings.append(
            Finding({
                "name": "Potential Flash Loan Attack",
                "description": f"Flash Loan detected with hash: { transaction_event.hash }",
                "alert_id": "FORTA-5",
                "protocol": "AAVE",
                "type": FindingType.Suspicious,
                "severity": FindingSeverity.Low
            })
        )

    return findings
