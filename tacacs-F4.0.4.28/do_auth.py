#!/usr/bin/python

# Program I threw together to do the things tac_plus won't
# It allows very granular control. Please visit tacacs.org as
# this is continually updated

# History:
# Version 1.1
# Simple typo - a stray 's' botched a deny statement

# Version 1.2
# Did you know a firewall doesn't end it's commands with a <cr>?

# Version 1.3
# Needs a default user.  If most of your users have the same access,
# and you have a default access in tac_plus.conf, you need it here as
# well.

# Version 1.4
# CRS doesn't send $address when in conf t
# Added -fix_crs_bug as as simple/stupid workaround

# Version 1.5
# Mistake in the example, thanks to aojea

# Version 1.6
# Added support for other services besides service=shell
# (ie - they work, by they match on IP/Source only.  If you have examples of
# pairs other than cmd to match on, please bring them to my attention)

# Version 1.7
# Fixed reression
# Support for replacing av pairs

# Version 1.8
# Nexus support (tac_pair format different)

# Version 1.9
# Better Nexus Support
# Only send roles to Nexus
# Better av pair replacement

# TO DO (If anybody bothers to request them)
# Possible web front end - simple cgi shouldn't be too hard to write
# More work on tac_pairs - sniff wlc traffic
# Write a better option parser to ignore options not sent (See CRS Bug)

'''
do_auth.py [-options]
Version 1.9
do_auth is a python program I wrote to work as an authorization script for 
tacacs to allow greater flexability in tacacs authentication.  It allows
a user to be part of many predefined groups that can allow different
access to different devices based on ip, user, and source address.  

Do not play with do_auth untill you have a firm grasp on tac_plus!

 -u Username.  Mandatory.  $user
 -i Ip address of user.  Optional.  If not specified, all host_ entries
    are ignored and can be omitted. $address
    **Note: If you use IOS-XR, you MUST add -fix_crs_bug after $address
    due to a bug in IOS-XR
 -d Device address.  Optional.  If not specified, all device_ entries
    are ignored and can be omitted.  $name
 -f Config Filename.  Default is do_auth.ini.
 -l Logfile. Default is log.txt.
 -D Debug mode.  Allows you to call the program without reading 
    from stdin.  Useful to test your configuration before going
    live.  Sets a default command of "show users wides".

Groups are assigned to users in the [users] section.  A user must
be assigned to one or more groups, one per line.  Groups are defined 
in brackets, but can be any name.  Each group can have up to 6 options 
as defined below.

host_deny   Deny any user coming from this host.  Optional.
host_allow      Allow users from this range.  Mandatory if 
        -i is specified.
device_deny Deny any device with this IP.  Optional.
device_permit   Allow this range.  Mandatory if -d is specified
command_deny    Deny these commands.  Optional.
command_permit  Allow these commands.  Mandatory.
av_pairs    list of av pairs to replace if found. Optional - be careful 

The options are parsed in order till a match is found.  Obviously, 
for login, the commands section is not parsed.  If a match is not
found, or a deny is found, we move on to the next group.  At the
end, we have an implicit deny if no groups match.  

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
device_permit = 
    10.1.1.*
command_permit =
    .*
[television_group]
host_allow =
    .*
device_permit = 
    .*
command_permit = 
    show.*
    
Example tacacs line: after authorization "/usr/bin/python 
/root/do_auth.pyc -i $address -fix_crs_bug -u $user -d $name -l /root/log.txt
-f /root/do_auth.ini"
(that's one line)

Example av_pair:
The following example will replace any priv-lvl with priv-lvl=1 ONLY if passed.
Think of "av_pairs" as a find/replace function.

av_pairs =
    priv-lvl=1

Brocade has a brocade-privlvl which I like.  It maps priv-lvl to 
brocade-privlvl, but priv-lvl=1 results in interface privileges.  Here
is an example of how to map to brocade-privlvl=5 which has no modification
rights.  Unfortunately, it does require you to put in the IP's of your gear.
The following group would go before other groups:

[brocade_readonly]
host_allow =
    .*
device_permit =
    192.168.1.*
command_permit =
    .*
av_pairs =
    priv-lvl,brocade-privlvl=5

You could also put "priv-lvl=15,brocade-privlvl=5" or whatever your
tac_plus deamon is passing; as long as it's a match it accomplished the same
thing.  In this example, we essentially replace the whole av_pair resulting 
in the user having only read access.  Alternatively, a good "disable account"
can be created by simpley doing:

av_pairs =
    brocade-privlvl=5

This results in the brocades having read/only, and the Cisco's go into disable
because they don't understand it.  (We're assuming that the user has no enable
account or the priv-lvl is pointless)  You could also add a shell role for nexus,
which we will discuss next.  (shell:roles="network-admin")  

NEXUS - Due to a slight change in the nexus, do_auth is able to 
discern if a device is a nexus or not.  In tac_plus, do the following:

        service = exec {
                priv-lvl = 1 
                shell:roles=\"\\"network-operator\\""
                idletime = 3 
                timeout = 15
        }   
        after authorization <do_auth yada yada>

This configuration does NOT work without do_auth.  However, WITH do_auth, 
do_auth will only send shell:roles to Nexus switches, allowing your
other gear to work correctly.  Simply put av_pairs in your do_auth, and
it will figure it out for you.  (If not, it won't touch them.   The logic is
simple: If (av_pairs in .ini): Then (do_stuff), Else (exit(2)- Don't modify 'em!))

Roles can also be modified in a do_auth group, as below:

av_pairs = 
        priv-lvl=15
        shell:roles="network-admin"

Also of note, you MUST USE DOUBLE QUOTES to get tac_plus to correctly
pass "network-operator" in the service example above.  UNLESS you are 
modifying the key with do_auth in av_pairs - it will fix the quotes.

BUGS: You must know your regular expressions.  If you enter a bad
expression, such as *. instead of .*, python re will freak out and 
not evaluate the expression. (Thought about netaddr, but would you
really install it?)

CAVEATS: One group can not take away what another group grants via deny.
If a match is not found, it will go on to the next group.  If a deny is 
matched, it will go on to the next group.  
Order is crucial - the groups should go from more specific to less 
specific.  In the above example, if television_group was put before
simpson_group, simpson_group would never be called because 
televsion_group catches everything in device_permit.  

HELP: If somebody has a WLC or other unknown network equipment, I 
require some testing/sniffing done - thanks!!

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 or any
later version as published by the Free Software Foundation, 
http://www.gnu.org/

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

Written by Dan Schmidt - Please visit tacacs.org to check for updates.
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

# Can't make it part of get_attribute... oh well...
# We need someway to check to see if a username exists with out exit(1)
def check_username(config, log_file, user_name):
    if not config.has_section('users'):
        log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
                + "Error: users section doesn't exist!")
        sys.exit(1)
    if config.has_option('users', user_name):
        return True
    else:
        return False

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
        optlist, args = getopt.getopt(sys.argv[1:], 'i:u:f:l:d:?:D', ['fix_crs_bug','?', '-?', 'help', 'Help'])
    except getopt.GetoptError, err:
        print str(err) 
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
#DEBUG!  We at least got CALLED
#   log_file.write('Hello World!' + '\n')
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
#DEBUG - print tac pairs
#    for item in av_pairs:
#        log_file.write(item)

# Function to make cmd's readable
# Not very good, but will do for now
# I don't use any other service other than shell to test!
    the_command = ""
    return_pairs = ""
    if (av_pairs[0] == "service=shell\n"):  
        if av_pairs[1] == ("cmd=\n"): # #&*@ Nexus!
            if len(av_pairs) > 2:
                #DEBUG
                # log_file.write('Nexus pairs found\n')
                return_pairs = av_pairs[2:] #strip the "cmd=" for consistency
#Commands - Concatenate to a readable command
        elif av_pairs[1].startswith("cmd="):
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
            #DEBUG - We got the command
            #log_file.write(the_command + '\n')
#Login - Get av_pairs to pass back to tac_plus
        elif av_pairs[1].startswith("cmd*"):  #Anybody know why it's "cmd*"?
            if len(av_pairs) > 2:
                return_pairs = av_pairs[2:] #You MUST strip the "cmd*" av-pair
# Definately not a Nexus, so strip any nexus pair 
            for item in return_pairs:
                if item.startswith("shell:roles"):
                    return_pairs.remove(item)
    else:
         return_pairs = av_pairs
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

# If the user doesn't exist, just use the default settings
# Kind of a hack, but it works because we only get_attribute on user_name once.
# We have the : in there which we can use to split if required
    if not check_username(config, log_file, user_name):
        user_name = (user_name + ":(default)")
        groups = get_attribute(config, "users", "default", log_file, filename)
    else:
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
                #Stupid IOS-XR
                if ip_addr == "-fix_crs_bug":
                    pass
                elif this_group == groups[-1]:
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
        # Attempt to modify return pairs
        want_tac_pairs = False
        if config.has_option(this_group, "av_pairs"):
            temp_av_pairs = get_attribute(config, this_group, "av_pairs", log_file, filename)
            i = 0
            for item in return_pairs:
                splt = item.split('=')
                if len(splt) > 1:
                    #DEBUG
                    #for thing in splt:
                    #    log_file.write('Thing:' + thing + '\n')
                    for item2 in temp_av_pairs:
                        item2 = item2.strip()
                        if item2.find(',') > -1: 
                            splt2 = item2.split(',')
                            if len(splt2) > 1:
                                #splt3 = splt2[0].split('=')
                                if splt[0].find(splt2[0]) > -1:
                                    want_tac_pairs = True
                                    return_pairs[i] = ('%s' % splt2[1])
                        else:
                            splt2 = item2.split('=')
                            if len(splt2) > 1:
                                if splt[0] == splt2[0].strip(): # strip needed?
                                    want_tac_pairs = True
                                    #DEBUG
                                    #log_file.write("Replacing pairs %s=%s\n" %
                                    #               (splt2[0].strip(),
                                    #                splt2[1].strip()))
                                    return_pairs[i] = ('%s=%s' % (splt2[0].strip(),
                                                                 splt2[1].strip()))
                i = i + 1

        # The previous 4 statements are to deny, it we passed them, proceed
        # If we are logging in, return pairs, if not, go no to check the command
        # Yes, simply printing them is how you return them

        # First, let's make sure we're doing service = shell.  If not, just
        # allow it.  I currently have little knowledge of cmd's sent by other
        # services which is why this code is a little klugy. 
        if return_pairs:
            splt = av_pairs[0].split('=') # Removed service in return_pairs
            if len(splt) > 1:
                if not splt[1].strip() == 'shell': 
                    log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
                         + "User '%s' granted non-shell access to device '%s' in group '%s' from '%s'\n"
                         % (user_name, device, this_group, ip_addr))
                    return_pairs = av_pairs[2:] # Cut the first two?
                    for item in return_pairs:
                        #DEBUG
                        # log_file.write("Returning:%s\n" % item.strip())
                        print item.strip('\n')
                    if want_tac_pairs:
                        #DEBUG
                        # log_file.write("Exiting status 2\n")
                        sys.exit(2)
                    else:
                        #DEBUG
                        # log_file.write("Exiting status 0\n")
                        sys.exit(0) # Don't even TRY to mess with the tac pairs
        #Proceed with shell stuff
        if not len(the_command) > 0:
            #DEBUG
            # log_file.write("not len(the_command) > 0\n")
            for item in return_pairs:
                #DEBUG
                # log_file.write("Returning:%s\n" % item.strip())
                print item.strip('\n')
            log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
                 + "User '%s' granted access to device '%s' in group '%s' from '%s'\n"
                 % (user_name, device, this_group, ip_addr))
            sys.exit(2)
        else:   # Check command
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
            else:   #exit & log if last group
                if this_group == groups[-1]:
                    log_file.write(strftime("%Y-%m-%d %H:%M:%S: ")
                        + "User '%s' not allowed command '%s' to device '%s' in any group\n"
                         % (user_name, the_command, device))
                    #Can't... remember why I added this given the implicit deny  
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
