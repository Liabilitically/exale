from dotenv import load_dotenv
from google.cloud import firestore
from google.cloud.firestore import FieldFilter

load_dotenv()

db = firestore.Client()

def is_user_allowed(user_email: str) -> bool: # ✅
    doc_ref = db.collection('users').document(user_email)
    return doc_ref.get().exists

def is_msg_classified(user_email: str, message_id: str) -> bool: # ✅
    doc_ref = db.collection('users').document(user_email).collection('classified_emails').document(message_id)
    return doc_ref.get().exists

def store_new_classified_message(user_email: str, message_id: str, lead: bool, subject: str, sender: str, snippet: str) -> None: # ✅
    db.collection('users') \
    .document(user_email) \
    .collection('classified_emails') \
    .document(message_id) \
    .set({
        "lead": lead,
        "drafted": False,
        "subject": subject,
        "sender": sender,
        "snippet": snippet,
        "timestamp": firestore.SERVER_TIMESTAMP,
    })

def get_all_stored_leads(user_email: str) -> dict:
    docs = (
        db.collection('users').document(user_email).collection('classified_emails')
        .where(filter=FieldFilter("lead", "==", True))
        .stream()
    )

    stored_leads = {}

    for doc in docs:
        stored_leads[doc.id] = doc.to_dict()

    return stored_leads

def get_user_industry(user_email: str) -> str:
    doc = db.collection('users').document(user_email).get()
    return doc.to_dict()['industry']

def set_message_to_drafted(user_email: str, message_id: str) -> None: # ✅
    db.collection('users') \
    .document(user_email) \
    .collection('classified_emails') \
    .document(message_id) \
    .update({
        "drafted": True,
    })