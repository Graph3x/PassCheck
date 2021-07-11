import re
from nltk.corpus import words
import nltk
import sys
import datetime
import requests
import hashlib
import json

passwd = ""

has_numbers = False
has_upper = False
has_lower = False
has_special = False
score = 0


def CheckLength(pwd):
	global score
	if len(pwd) < 6:
		return "Password is too short! You should use 12 or more characters."
	elif len(pwd) < 8:
		score += 4
		return "Password should be longer. You should use 12 or more characters."
	elif len(pwd) < 10 or len(pwd) == 10:
		score += 14
		return "Password is long enough, but longer would still be recommended. You should use 11 or more characters."
	elif len(pwd) > 10:
		score += 26
		return "Password length is perfect!"


def CheckChars(pwd):
	global score
	problems = []
	global has_numbers
	global has_upper
	global has_lower
	global has_special

	if re.search('\d+', pwd):
		has_numbers = True
		score += 2
	else:
		problems += ["numbers"]

	if pwd.lower() != pwd:
		has_upper = True
		score += 2
	else:
		problems += ["uppercase letters"]

	if pwd.upper() != pwd:
		has_lower = True
		score += 2
	else:
		problems += ["lowercase letters"]

	if (bool(re.search('^[a-zA-Z0-9]*$',pwd))==False):
		has_special = True
		score += 4
	else:
		problems += ["special characters"]

	if has_lower and has_upper and has_special and has_numbers:
		return "Password has all types of characters!"

	else:
		ans = ""
		for i, problem in enumerate(problems):
			ans += problem
			if i + 1 != len(problems):
				ans += ", " 


		return "Password is missing " + ans


def CheckLastChar(pwd):
	global score
	pw = pwd[:len(pwd)-1]

	if (not re.search('\d+', pw)) and has_numbers:
		return "Password's only number shouldn't be at the end!"

	if  (bool(re.search('^[a-zA-Z0-9]*$', pw))==True) and has_special:
		return "Password's only special character shouldn't be at the end!"

	else:
		if has_special and has_numbers:
			return "Password has good placement of special characters and numbers."
			score += 6
		elif has_special:
			return "Password has good placement of special characters."
			score += 3
		elif has_numbers:
			return "Password has good placement of numbers."
			score += 3
		else:
			return "Can't check for placement of special characters and numbers."


def CheckFirstChar(pwd):
	global score
	pw = pwd[1:]
	if pw.lower() == pw and has_upper:
		return "Password's only uppercase letter shouldn't be first!"
	elif has_upper:
		score += 2
		return "Password has good use of upercase characters."
	else:
		return "No uppercase characters to check!"


def CheckWords(pwd):
	global score
	if "".join(re.findall("[a-zA-Z]+", pwd)).lower() in set(words.words()):
		return "Found this word in your password: " + "".join(re.findall("[a-zA-Z]+", pwd)) + ". Using a single word is not recommended!"
	else:
		score += 2
		return "No single english word found in you password. Still make sure to not use a single word. Using mutiple words is better, but still not recommended."


def CheckLeetSpeak(pwd):
	global score
	paswd = pwd
	pwd = pwd.replace('1', 'l')
	pwd = pwd.replace('3', 'e')
	pwd = pwd.replace('4', 'a')
	pwd = pwd.replace('@', 'a')
	pwd = pwd.replace('5', 's')
	pwd = pwd.replace('7', 't')
	pwd = pwd.replace('0', 'o')

	if "".join(re.findall("[a-zA-Z]+", pwd)).lower() in set(words.words()) and not "".join(re.findall("[a-zA-Z]+", paswd)).lower() in set(words.words()):
		return "Password might have letters replaced with numbers, which is not safe! Word found: " + ''.join(re.findall('[a-zA-Z]+', pwd))

	else:
		score += 2
		return "Password doesn't seem to have letters replaced by numbers."


def CheckYears(pwd):
	global score
	try:
		nums = "".join(re.findall("[0-9]+", pwd))
		if int(nums) > 1900 and int(nums) < int(datetime.datetime.now().date().strftime("%Y")):
			return "Password includes a possible birth year!: " + str(nums)

		else:
			score += 2
			return "Password does not include a realistic birth year."

	except ValueError:
		return "Password does not include a realistic birth year."


def CalculateEntropy(pwd):
	letters = "".join(re.findall("[a-zA-Z]+", pwd))
	iletters = len(letters)

	numbers = "".join(re.findall("[0-9]+", pwd))
	inumbers = len(numbers)

	ispecial = len(pwd) - iletters - inumbers

	if has_upper and has_lower:
		iletters += iletters

	entropy = (iletters ** 26) + (inumbers ** 10) + (ispecial ** 30)
	return "Password entropy  is " + str(entropy)


def TimeToCrack(pwd):
	possible_characters = 0
	ln = len(pwd)

	if has_upper:
		possible_characters += 26
	if has_lower:
		possible_characters += 26
	if has_numbers:
		possible_characters +=10
	if has_special:
		possible_characters += 30

	possible_passwords = possible_characters ** ln
	
	ntml = possible_passwords / 348000000000
	SHA1 = possible_passwords / 20000000000
	SHA512 = possible_passwords / 364000
	PBKDF2 = possible_passwords / 196000
	BCrypt = possible_passwords / 71000

	times = {"ntml": ntml, "SHA1": SHA1, "SHA512": SHA512, "PBKDF2": PBKDF2, "BCrypt": BCrypt}
	print("TIME TO BRUTEFORCE BY HASHING ALGORITHM:")
	for key in times.keys():
		if times[key] > 31557600000:
			timer = "millenniums"
			times[key] =  times[key] / 31557600000
		elif times[key] > 3155760000:
			timer = "centuries"
			times[key] =  times[key] / 3155760000
		elif times[key] > 315576000:
			timer = "decades"
			times[key] =  times[key] / 315576000
		elif times[key] > 31557600:
			timer = "years"
			times[key] =  times[key] / 31557600
		elif times[key] > 86400:
			timer = "days"
			times[key] =  times[key] / 86400
		elif times[key] > 3600:
			timer = "hours"
			times[key] =  times[key] / 3600
		elif times[key] > 60:
			timer = "minutes"
			times[key] =  times[key] / 60
		elif times[key] > 1:
			timer = "seconds"
		elif times[key] < 1:
			timer = "microseconds"
			times[key] =  times[key] * 1000000

		print(f"{key}: {int(times[key])} {timer} .")
	


def hibp(pwd):
	global score
	hasho = hashlib.sha1(bytearray(pwd, 'utf-8'))
	hash5 = hasho.hexdigest()[:5]
	url = f"https://api.pwnedpasswords.com/range/{hash5}"
	headers = {"user-agent": "PassCheck"}

	response = requests.get(url, headers = headers)

	passesr = response.text.split('\n')
	data = {}
	for passr in passesr:
		passn = passr.split('\r')[0].lower()
		data.update({hash5 + passn.split(':')[0] : passn.split(':')[1]})

	if str(hasho.hexdigest()) in data.keys():
		score = 0
		return f"Your password has been found in {data[str(hasho.hexdigest())]} HaveIBeenPwned breaches!"
	else:
		score += 6
		return "No HaveIBeenPwned breaches found"


def final():
	if score == 0:
		return "Your password is freely viable on the internet! Get a new one ASAP. Go to HaveIBeenPwned to see if it is associated to your email!"
	elif score == 50:
		return "SCORE: 50/50... The password looks great!"
	elif score > 40:
		return f"SCORE: {score}. The password is not perfect, but it should do the job"
	elif score > 30:
		return f"SCORE: {score}. Change is not neccessary, but you might thing about getting better password soon."
	elif score > 20:
		return f"SCORE: {score}. The password is weak, but not awful. You should still get better one though."
	elif score < 20:
		return f"SCORE: {score}. The password is very weak. Get a better one ASAP"


if __name__ == '__main__':

	passwd = input("Enter password:		")

	try:
		nltk.data.find('corpora/words')
	except LookupError:
		nltk.download('words')
		sys.exit()

	print(CheckLength(passwd))
	print(CheckChars(passwd))
	print("\n")

	print(CheckLastChar(passwd))
	print(CheckFirstChar(passwd))
	print("\n")

	print(CheckWords(passwd))
	print(CheckLeetSpeak(passwd))
	print(CheckYears(passwd))
	print("\n")

	print(CalculateEntropy(passwd))
	print("\n")
	TimeToCrack(passwd)
	print("\n")
	print(hibp(passwd))
	print("\n")
	print("Check finished!")

	print("\n")
	print(final())
