import getpass,sys
from blackbox.accounts import add
from blackbox.storage import init_db
init_db()
username=input('Username: ').strip()
password=getpass.getpass('Password (16+ chars): ')
confirmation=getpass.getpass('Confirm: ')
if password!=confirmation:sys.exit('Passwords do not match')
add(username,password)
print('Account created. Restart BLACKBOX and log in using your browser.')
