# Intentionally insecure example for HW3 security analysis.
# All values are fictional test data.

password = "FAKE_DEMO_PASSWORD_123"

def find_user(username):
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return query
