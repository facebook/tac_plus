#!/usr/bin/python

# Program I am writing to do the things tac_plus won't
# It will allow very granular control.

# Version 1.1
# Simple typo - a stray 's' botched a deny statement

# Version 1.2
# Did you know a firewall doesn't send a cmd-arg=<cr>?


'''
do_auth.py [-options]
Version 1.2

do_auth is a python program I wrote to work as an authorization script for 
tacacs to allow greater flexability in tacacs authentication.  It allows
a user to be part of many predefined groups that can allow different
access to different devices based on ip, user, and source address.  

Do not play with do_auth untill you have a firm grasp on tac_plus!

 -u	Username.  Mandatory.  $user
 -i	Ip address of user.  Optional.  If not specified, all host_ entries
 	are ignored and can be omitted. $address
 -d	Device address.  Optional.  If not specified, all device_ entries
 	are ignored and can be omitted.  $name
 -f	Config Filename.  Default is do_auth.ini.
 -l	Logfile. Default is log.txt.
 -D	Debug mode.  Allows you to call the program without reading 
 	from stdin.  Useful to test your configuration before going
	live.  Sets a default command of "show users wides".

Groups are assigned to users in the [users] section.  A user must
be assigned to one or more groups, one per line.  Groups are defined 
in brackets, but can be any name.  Each group can have up to 6 options 
as defined below.

host_deny  	Deny any user coming from this host.  Optional.
host_allow  	Allow users from this range.  Mandatory if 
		-i is specified.
device_deny	Deny any device with this IP.  Optional.
device_permit	Allow this range.  Mandatory if -d is specified
command_deny	Deny these commands.  Optional.
command_permit	Allow these commands.  Mandatory.

The options are parsed in order till a match is found.  Obviously, 
for login, the commands section is not parsed.  If a match is not
found, or a deny is found, we move on to the next group.  At the
end, we have an implicit deny if no groups match.  All tacacs keys
passed on login to do_auth are returned.  (except cmd*)  It is 
possible to modify them, but I haven't implemented this yet as
I don't need it.  Future versions may have an av_pair & 
append_av_pair option.

An simple example is as follows.

[users]
homer =
	simpson_group
	television_group
stimpy =
	television_group
[simpson_group]
host_deny = 
	1.1.1.1
	1.1.1.2
host_allow = 
	1.1.1.*
device_allow = 
	10.1.1.*
command_permit =
	.*
[television_group]
host_allow =
	.*
device_allow = 
	.*
command_permit = 
	show.*
	
Example tacacs line: after authorization "/usr/bin/python 
/root/do_auth.pyc -i $address -u $user -d $name -l /root/log.txt
-f /root/do_auth.ini"
(that's one line)

BUGS: You must know your regular expressions.  If you enter a bad
expression, such as *. instead of .*, python re will freak out and 
not evaluate the expression.  Designed for exec - I don't have
any ppp/ect equipment to test, or rather I do, but I don't have
time to mess with it. 

CAVEATS: One group can not take away what another group grants.  If
a match is not found, it will go on to the next group.  If a deny is 
matched, it will go on to the next group.  
Order is crucial - the groups should go from more specific to less 
specific.  In the above example, if television_group was put before
simpson_group, simpson_group would never be called because 
televsion_group catches everything in device_allow.  

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 or any
later version as published by the Free Software Foundation, 
http://www.gnu.org/

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

Written by Dan Schmidt
'''

import sys,re,getopt,ConfigParser
from time import strftime

# I really don't want to deal with these exceptions more than once
# filename is only used in log statements
def get_attribute(config, the_section, the_option, log_file, filename):
	if not config.has_section(the_section):
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				 + "Error: Section '%s' does not exist in %s\n" 
				 % (the_section, filename))
		sys.exit(1)
	if not config.has_option(the_section, the_option):
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				 + "Error: Option '%s' does not exist in section %s in file %s\n" 
				 % (the_option, the_section, filename))
		sys.exit(1)
	#Should not have any exceptions - BUT, just in case
	try:
		attributes = config.get(the_section, the_option)
	except ConfigParser.NoSectionError:
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				+ "Error: Section '%s' Doesn't Exist!\n" 
				% (the_section))
		sys.exit(1)
	except ConfigParser.DuplicateSectionError:
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				+ "Error: Duplicate section '%s'\n" 
				% (the_section))
		sys.exit(1)
	except ConfigParser.NoOptionError:
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
					+ "Error: '%s' not found in section '%s\n'" 
					 % (the_option, the_section))
		sys.exit(1)
	#To do: finish exceptions. 
	except ConfigParser.ParsingError:
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				+ "Error: Can't parse file '%s'! (You got me)\n" 
			 % (filename))
		sys.exit(1)
	attributes = attributes.split('\n')
	#Strip empty lines
	attributes2 = []
	for line in attributes:
		if line:
			attributes2.append(line)
	return attributes2

# If match item in our_list, true, else false
# Example - if deny section has a match for 10.1.1.1, 
# return True, else False
# If the section doesn't exist, we assume an 
# impicity deny/false

def match_it(the_section, the_option, match_item, config, log_file, filename):
	if config.has_option(the_section,the_option):
		our_list = get_attribute(config, the_section, the_option, log_file, filename)
		for item in our_list:
#p = re.compile(item) Not necessary - we're only using it once
			if re.match(item,match_item):
				return True
	return False
 
def main():
	#Defaults
	filename = "do_auth.ini"
	log_name = "log.txt"
	user_name = ""
	ip_addr = ""
	device = ""
	is_debug = False
	
	argv = sys.argv
	try:
		optlist, args = getopt.getopt(sys.argv[1:], 'i:u:f:l:d:?:D', ['?', '-?', 'help', 'Help'])
	except getopt.GetoptError, err:
		print str(err) # will print something like "option -a not recognized"
		print __doc__
	        sys.exit(1)
	for (i, j) in optlist:
		if i == '-i':
			ip_addr = j
		elif i == '-u':
			user_name  = j
		elif i == '-f':
			filename = j
		elif i == '-l':
			log_name = j
		elif i == '-d':
			device = j
		elif i in ('?', '-?', 'help', 'Help'):
			print __doc__
			sys.exit(1)
		elif i == '-D':
			is_debug = True
		else:
			print 'Unknown option:', i
			sys.exit(1)
	if len(argv) < 7:
		print __doc__
		sys.exit(1)
	log_file = open (log_name, "a")
#read AV pairs
	av_pairs = []
	if not (is_debug):
		for line in sys.stdin:
			av_pairs.append(line)
	else:
		#Default Debug command is "show users wide"
		#Later versions will allow this to be set
		av_pairs.append("service=shell\n")
		av_pairs.append("cmd=show\n")
		av_pairs.append("cmd-arg=users\n")
		av_pairs.append("cmd-arg=wide\n")
		av_pairs.append("cmd-arg=<cr>\n")
#DEBUG
#	for item in av_pairs:
#		log_file.write(item)

# Function to make cmd's readable
# Not very good, but will do for now
# I don't use any other service other than shell to test!
	the_command = ""
	return_pairs = ""
	if (av_pairs[0] == "service=shell\n"):	
#Commands - Concatenate to a readable command
		if av_pairs[1].startswith("cmd="):
			our_command = av_pairs[1].split("=")
			the_command = our_command[1].strip('\n')
			if len(av_pairs) > 2:
				i = 2
				our_command = av_pairs[i].split("=")
				while not (our_command[1] == "<cr>\n"):
					the_command = the_command + " " + our_command[1].strip('\n')
					i = i + 1
					if i == len(av_pairs): # Firewalls don't give a <cr>!!
						break
					our_command = av_pairs[i].split("=")
			#DEBUG
			#log_file.write(the_command + '\n')
#Login - Get av_pairs to pass back to tac_plus
		if av_pairs[1].startswith("cmd*"):	#Anybody know why it's "cmd*"?
			return_pairs = av_pairs[2:]	#You have to strip the "cmd*" av-pair
	if not user_name:
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				+ "Error: No username entered!\n")
		sys.exit(1)
	config = ConfigParser.SafeConfigParser()
	if not (filename in config.read(filename)):
		log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				+ "Error: Can't open/parse '%s'\n" 
				 % (filename))
		sys.exit(1)
	the_section = "users"

	groups = get_attribute(config, "users", user_name, log_file, filename)
	for this_group in groups:
		if ip_addr:
			if match_it(this_group, "host_deny", ip_addr, config, log_file, filename):
				if this_group == groups[-1]:
					log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
						+ "User '%s' denied from source '%s' in '%s'->'%s'\n"
						 % (user_name, ip_addr, this_group, "host_deny"))
					sys.exit(1)
				else:
				# HUM... afterthought.  We need it to continue if more groups exist
					continue
			if not match_it(this_group, "host_allow", ip_addr, config, log_file, filename):
				if this_group == groups[-1]:
					log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
						+ "User '%s' not allowed from source '%s' in '%s'->'%s'\n"
						 % (user_name, ip_addr, this_group, "host_allow"))
					sys.exit(1)
				else:
					continue
		if device:
			if match_it(this_group, "device_deny", device, config, log_file, filename):
				if this_group == groups[-1]:
					log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
						+ "User '%s' denied access to device '%s' in '%s'->'%s'\n"
						 % (user_name, device, this_group, "device_deny"))
					sys.exit(1)
				else:
					continue
			if not match_it(this_group, "device_permit", device, config, log_file, filename):
				if this_group == groups[-1]:
					log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
						 + "User '%s' not allowed access to device '%s' in '%s'->'%s'\n"
						 % (user_name, device, this_group, "device_permit"))
					sys.exit(1)
				else:
					continue
		# The previous 4 statements are to deny, it we passed them, proceed
		# If we are logging in, return pairs, if not, go no to check the command
		# Yes, simply printing them is how you return them
		if not len(the_command) > 0:
			for item in return_pairs:
				print item.strip('\n')
			log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
				 + "User '%s' granted access to device '%s' in group '%s' from '%s'\n"
				 % (user_name, device, this_group, ip_addr))
			sys.exit(2)
		else:	# Check command
			if match_it(this_group, "command_deny", the_command, config, log_file, filename):
				if this_group == groups[-1]:
					log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
						+ "User '%s' denied command '%s' to device '%s' in '%s'->'%s'\n"
						 % (user_name, the_command, device, this_group, "command_deny"))
					sys.exit(1)
				else:
					continue
			elif match_it(this_group, "command_permit", the_command, config, log_file, filename):
				log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
					+ "User '%s' allowed command '%s' to device '%s' in '%s'->'%s'\n"
					 % (user_name, the_command, device, this_group, "command_permit"))
				sys.exit(0)
			else:	#exit & log if last group
				if this_group == groups[-1]:
					log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
						+ "User '%s' not allowed command '%s' to device '%s' in any group\n"
						 % (user_name, the_command, device))
					#Hum... this only works if it's the last group/only group.  
					sys.exit(1)
				else:
					continue


	#implicit deny at the end
	log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
		+ "User '%s' not allowed access to device '%s' from '%s' in any group\n"
		 % (user_name, device, ip_addr))
	sys.exit(1)
			
if __name__ == "__main__":
    main()
