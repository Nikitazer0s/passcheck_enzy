import requests
import hashlib
import sys


# Request API password data, return error code if failed
def reqests_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/'+ query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
	return res
# Compare all hashed password tails to our passwords tail and return count
def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes: 
		if h == hash_to_check:
			return count
	return 0
# Convert password to SHA1 algo encoding,give first 5 password chars to API and get list of all tailed hashes
def pwn_api_check(password):
	sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1pass[:5], sha1pass[5:]
	response = reqests_api_data(first5_char)
	return get_password_leaks_count(response, tail)

# Recieve password input from user, if password was found return count of times it was found
def main(args):
	for password in args:
		count = pwn_api_check(password)
		if count:
			print(f'{password} was found {count} times...')
		else:
			print("hasn't been hacked")
	return 'done!'	

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))

