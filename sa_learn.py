#!/usr/bin/python

import re
import sys
import dbm

from time import asctime, strftime, strptime
from os import listdir, stat
from os.path import basename, exists, join, splitext
from subprocess import call, Popen, PIPE, STDOUT
from pwd import getpwnam, getpwuid
from grp import getgrnam, getgrgid
from mailbox import Maildir

NAME        = basename(__file__)
VERSION     = '1.2'

SERVERNAME  = 'mail.rabbittsoup.com'
SERVERROOT  = '/Applications/Server.app/Contents/ServerRoot'
DATADIR     = '/Library/Server/Mail/Data'
CONFIGDIR   = '/Library/Server/Mail/Config'
LOGDIR      = '/Library/Logs/Mail'
LOGPATH     = LOGDIR + '/junkmail.log'
SERVERADMIN = SERVERROOT + '/usr/sbin/serveradmin'
SALEARNPATH = SERVERROOT + '/usr/bin/sa-learn'
DOVEADMPATH = SERVERROOT + '/usr/bin/doveadm'
PREFSPATH   = DATADIR + '/scanner/amavis/user_prefs'
SADBPATH    = DATADIR + '/scanner/amavis/.spamassassin'
DBPATH      = DATADIR + '/db'
MAILPATH    = DATADIR + '/mail'
MAILUSERS   = MAILPATH + '/users'
POSTFIXPATH = CONFIGDIR + '/postfix'

# look for the received header marking delivery between outside world and us
rcvdpat = re.compile(r'^from \[?(\S+)\]? \((\S+) \[(?!127.0.0.1)(?P<ip>\S+)\]\)\s+by (' + SERVERNAME + r') \(Postfix\) with (\S+) id (\S+)\s+for <\S+>; (.{3}), (?P<ts>.{20}) ((-|\+)\d{4}) \((?P<tz>\S+)\)$')

def log(message):
    time = asctime()
    with open(LOGPATH, 'a') as file:
        for line in message.splitlines():
            if not line: continue
            file.write(time)
            file.write(': ')
            file.write(NAME)
            file.write(': ')
            file.write(line)
            file.write('\n')

def main(argv):
    global NAME
    NAME = basename(argv[0])

    log('Version: ' + VERSION)

    sadbpathuid, sadbpathgid = stat(SADBPATH)[4:6]
    sadbpathusr = getpwuid(sadbpathuid).pw_name
    sadbpathgrp = getgrgid(sadbpathgid).gr_name

    mailpathuid, mailpathgid = stat(MAILPATH)[4:6]
    mailpathusr = getpwuid(mailpathuid).pw_name
    mailpathgrp = getgrgid(mailpathgid).gr_name

    # spamassassin learn
    for user in listdir(MAILUSERS):
        junk = join(MAILUSERS, user, '.Junk')
        if (exists(junk)):
            log(junk)
            log(Popen([SALEARNPATH, '--dbpath', SADBPATH, '--prefspath=' + PREFSPATH, '--spam', '--no-sync', join(junk, 'cur')], stdout = PIPE, stderr = STDOUT).communicate()[0])
            log(Popen([SALEARNPATH, '--dbpath', SADBPATH, '--prefspath=' + PREFSPATH, '--spam', '--no-sync', join(junk, 'new')], stdout = PIPE, stderr = STDOUT).communicate()[0])

        salvage = join(MAILUSERS, user, '.Salvage')
        if (exists(salvage)):
            log(salvage)
            log(Popen([SALEARNPATH, '--dbpath', SADBPATH, '--prefspath=' + PREFSPATH, '--ham', '--no-sync', join(salvage, 'cur')], stdout = PIPE, stderr = STDOUT).communicate()[0])
            log(Popen([SALEARNPATH, '--dbpath', SADBPATH, '--prefspath=' + PREFSPATH, '--ham', '--no-sync', join(salvage, 'new')], stdout = PIPE, stderr = STDOUT).communicate()[0])

    call(['chown', '-R', sadbpathusr + ':' + sadbpathgrp, SADBPATH])

    log('database synchronization')
    log(Popen(['sudo', '-u', sadbpathusr, '-H', SALEARNPATH, '--dbpath', SADBPATH, '--prefspath=' + PREFSPATH, '--sync'], stdout = PIPE, stderr = STDOUT).communicate()[0])

    # custom data harvest
    ipblocks = {}
    db = dbm.open(join(DBPATH, splitext(NAME)[0]), 'c', 0640)
    log('harvesting junk-mail IP addresses')
    try:
        for user in listdir(MAILUSERS):
            junk = join(MAILUSERS, user, '.Junk')
            if (exists(junk)):
                for msg in Maildir(junk):
                    id = msg.get('Message-ID')
                    for rcvd in msg.getheaders('Received'):
                        match = rcvdpat.match(rcvd)
                        if (match is not None): break

                    else:
                        log('received header not found for ' + id + ' in ' + junk)
                        continue

                    ts = strftime('%Y-%m-%d %H:%M:%S %Z', strptime(' '.join((match.group('ts'), match.group('tz'))), '%d %b %Y %H:%M:%S %Z'))
                    ip = match.group('ip')
                    i = db.get(ip, '{}')
                    try:
                        i = eval(i, {}, {})

                    except:
                        log('error evaluating data at database key ' + repr(ip))
                        continue

                    if (('Salvage' in i) and (ts in i['Salvage']) and (id in i['Salvage'][ts])):
                        j = i['Salvage']
                        k = j[ts]
                        k.remove(id)
                        if (not k): del j[ts]
                        if (not j): del i['Salvage']
                        db[ip] = repr(i).replace('set([', '{').replace('])', '}')
                    
                    j = i.get('Junk', {})
                    k = j.get(ts, set())
                    if (id in k): continue
                    k.add(id)
                    j[ts] = k
                    i['Junk'] = j
                    db[ip] = repr(i).replace('set([', '{').replace('])', '}')
                    
            salvage = join(MAILUSERS, user, '.Salvage')
            if (exists(salvage)):
                for msg in Maildir(salvage):
                    id = msg.get('Message-ID')
                    for rcvd in msg.getheaders('Received'):
                        match = rcvdpat.match(rcvd)
                        if (match is not None): break

                    else:
                        log('received header not found for ' + id + ' in ' + junk)
                        continue

                    ts = strftime('%Y-%m-%d %H:%M:%S %Z', strptime(' '.join((match.group('ts'), match.group('tz'))), '%d %b %Y %H:%M:%S %Z'))
                    ip = match.group('ip')
                    i = db.get(ip, '{}')
                    try:
                        i = eval(i, {}, {})

                    except:
                        log('error evaluating data at database key ' + repr(ip))
                        continue

                    try:
                        j = i['Junk']
                        k = j[ts]
                        k.remove(id)
                    
                    except KeyError:
                        pass
                    
                    else:
                        if (not k): del j[ts]
                        if (not j): del i['Junk']
                    
                    j = i.get('Salvage', {})
                    k = j.get(ts, set())
                    k.add(id)
                    j[ts] = k
                    i['Salvage'] = j
                    db[ip] = repr(i).replace('set([', '{').replace('])', '}')
    
        for ip in db.keys():
            ipblock = ip.rsplit('.', 1)[0]
            i = eval(db[ip], {}, {})
            if ('Salvage' in i):
                ipblocks[ipblock] = 'Salvage'
            
            elif ('Junk' in i):
                l = sum([len(v) for v in i['Junk'].itervalues()])
                try:
                    ipblocks[ipblock] += l
                    
                except KeyError:
                    ipblocks[ipblock] = l
                    
                except TypeError:
                    pass

    finally:
        db.close()

    # create rbl
    if (ipblocks):
        log('updating rbl_override')
        with open(join(POSTFIXPATH, 'rbl_override'), 'w') as file:
            for ipblock, count in sorted(ipblocks.iteritems(), key = lambda i: '{:0>3}{:0>3}{:0>3}'.format(*i[0].split('.'))):
                if ((count is 'Salvage') or (count < 10)): file.write('# ')
                file.write(ipblock)
                file.write(' ' * (19 - len(ipblock)))
                file.write('521 ')
                file.write(str(count))
                file.write('\n')

        log(Popen(['sudo', 'postmap', 'hash:' + join(POSTFIXPATH, 'rbl_override')], stdout = PIPE, stderr = STDOUT).communicate()[0])
        log(Popen(['sudo', 'postfix', 'reload'], stdout = PIPE, stderr = STDOUT).communicate()[0])

    # clean up by deleting old junk, and move salvaged to inbox
    log('cleaning up')
    for user in listdir(MAILUSERS):
        junk = join(MAILUSERS, user, '.Junk')
        if (exists(junk)):
            n = len(Popen(['sudo', '-u', mailpathusr, '-H', DOVEADMPATH, '-v', 'search', '-u', user, 'MAILBOX', 'Junk', 'SAVEDBEFORE', '30d'], stdout = PIPE, stderr = STDOUT).communicate()[0].splitlines())
            if (n > 0):
                log('expunging ' + str(n) + ' junk-mail from ' + junk)
                log(Popen(['sudo', '-u', mailpathusr, '-H', DOVEADMPATH, '-v', 'expunge', '-u', user, 'MAILBOX', 'Junk', 'SAVEDBEFORE', '30d'], stdout = PIPE, stderr = STDOUT).communicate()[0])

        salvage = join(MAILUSERS, user, '.Salvage')
        if (exists(salvage)):
            n = len(Popen(['sudo', '-u', mailpathusr, '-H', DOVEADMPATH, '-v', 'search', '-u', user, 'MAILBOX', 'Salvage', 'ALL'], stdout = PIPE, stderr = STDOUT).communicate()[0].splitlines())
            if (n > 0):
                log('moving ' + str(n) + ' not-junk-mail from ' + salvage)
                log(Popen(['sudo', '-u', mailpathusr, '-H', DOVEADMPATH, '-v', 'move', '-u', user, 'INBOX', 'MAILBOX', 'Salvage', 'ALL'], stdout = PIPE, stderr = STDOUT).communicate()[0])

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
