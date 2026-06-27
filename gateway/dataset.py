"""
dataset.py
A small, bundled sample dataset of phishing and legitimate email text so the
classifier trains and demonstrates out of the box. For a real deployment you
would train on a large public corpus (e.g. Enron + PhishTank / Nazario).

label: 1 = phishing, 0 = legitimate
"""

PHISHING = [
    "Urgent: your account has been suspended. Verify your password now to avoid permanent closure.",
    "Dear customer, we detected unusual login activity. Click here to confirm your identity immediately.",
    "Congratulations! You have won a 1000 gift card. Claim your prize by entering your bank details.",
    "Your PayPal account is limited. Update your billing information within 24 hours or it will be closed.",
    "HMRC: you are due a tax refund of 482.50 GBP. Submit your details to receive your payment.",
    "Security alert: someone tried to access your account. Reset your password using the link below.",
    "Final notice: your package could not be delivered. Pay the customs fee to release your parcel.",
    "Your mailbox is full and will be deactivated. Re-validate your credentials to keep your account active.",
    "We could not process your last payment. Confirm your card number to restore your subscription.",
    "Action required: verify your Microsoft account or it will be permanently deleted within 48 hours.",
    "You have an outstanding invoice. Open the attached document and enable macros to view it.",
    "Bank notification: your card has been blocked. Call this number or click to unblock immediately.",
    "Apple ID locked for security reasons. Verify now to regain access to your account and purchases.",
    "Important: update your account information to continue using our service without interruption.",
    "Your account will be charged 99.99 unless you cancel. Click here to dispute this transaction now.",
    "Netflix payment declined. Update your payment method now to avoid losing access to your account.",
    "Wire transfer request approved. Confirm the beneficiary details by replying with your login.",
    "Your password expires today. Click to keep your current password and avoid being locked out.",
    "Suspicious sign-in prevented. Confirm it was you by verifying your full account credentials here.",
    "Claim your inheritance of 5 million USD. Provide your passport and bank account to process funds.",
]

LEGITIMATE = [
    "Hi team, attaching the notes from this morning's standup. Let me know if I missed anything.",
    "Thanks for your order. Your items have shipped and should arrive within three to five business days.",
    "Reminder: our project sync is scheduled for Thursday at 2pm. Agenda is in the shared doc.",
    "Please find attached the quarterly report. Happy to walk through the figures on a call.",
    "Your monthly statement is now available. Log in to your account at your convenience to view it.",
    "Welcome aboard! Here is some information to help you get started in your first week.",
    "The maintenance window is complete and all services are back to normal. Thanks for your patience.",
    "Lunch is sorted for the workshop on Friday. Let me know any dietary requirements by Wednesday.",
    "Great work on the presentation today. The client was impressed with the analysis section.",
    "Here are the meeting minutes from yesterday. Action items are listed at the bottom.",
    "Your appointment is confirmed for Monday at 10am. Reply to this email if you need to reschedule.",
    "Following up on our conversation, I have shared the document with edit access for your review.",
    "The library books you requested are now ready for collection at the front desk.",
    "Thank you for subscribing to our newsletter. You can manage your preferences in settings anytime.",
    "Just checking in on the timeline for the deliverable. No rush, whenever you get a chance.",
    "Our office will be closed for the bank holiday on Monday. Normal hours resume Tuesday.",
    "Attached is the agenda for next week's review. Feel free to add any items before Friday.",
    "Congratulations on completing the training module. Your certificate is attached for your records.",
    "The invoice for last month is attached. Payment terms are 30 days as per our agreement.",
    "Hi, could you send over the updated figures when you have a moment? Thanks so much.",
]


def load_dataset():
    texts = PHISHING + LEGITIMATE
    labels = [1] * len(PHISHING) + [0] * len(LEGITIMATE)
    return texts, labels
