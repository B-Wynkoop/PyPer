###############################################
# Auth.log failed logins and suspicious IPs   #
# /var/log/auth.log                           #
# Try-Except for passing errors               #
# -Wynkoop                                    #
####################START######################

import platform

# Variables for f-string input 
failed = 0
success = 0
failed_ips = {}

# Check for linux platform and identify log path to auth.log
if platform.system() == "Linux":
	log_path = "/var/log/auth.log"
else:
	print("Supports Linux var/log/auth.log")
	exit()

# Find and open auth.log using try-except error conditions
try:
	with open(log_path, "r") as file:
		logs = file.readlines()

# If log path is incorrect, pass & print response of error
except FileNotFoundError:
	print(f"Could not find {log_path}")
	exit()

# If permissions are incorrect, pass & print response of error
except PermissionError:
	print("Permission Denied | Try Using Sudo Privileges!")
	exit()

# FOR loop to iterate through each line of the auth.log 
for line in logs:

	if "Failed password" in line:
		failed += 1 

# Segments each line by index to gather info
		try:
			parts = line.split()
			ip_index = parts.index("from") + 1
			ip = parts[ip_index]

			if ip not in failed_ips:
				failed_ips[ip] = 1 
			else:
				failed_ips[ip] += 1

# Excepts any value or index error that may occur
		except (ValueError, IndexError):
			pass

	elif "Accepted password" in line: 
		success += 1 

# Print statement of the login report
print("\n<+* Log Report *+>")

print(f"Failed Logins: {failed}")
print(f"Successful Logins: {success}")

# Print statement of IP addresses with failed attempts >= 3 
print("\nUnknown or Suspicious IPs:")

for ip, count in failed_ips.items():
	if count >= 3:
		print(f"{ip} - {count} failed attempts")


#####################END#######################
