#!/usr/bin/env python3
#
# Copyright (c) 2021 Rodent Control
#
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#                    Version 2, December 2004
#
# Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
#
# Everyone is permitted to copy and distribute verbatim or modified
# copies of this license document, and changing it is allowed as long
# as the name is changed.
#
#            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
#   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
#
#  0. You just DO WHAT THE FUCK YOU WANT TO.
#

import socket
import select
import time
import itertools
import sys
import secrets
import re
import enum
import html

import argparse

RESPONSE_TIMEOUT = 1.0
QUERY_RETRIES = 1

COLOR_RESET = '\033[0m'
ARENA_COLORS = {
        '0' : '\033[0;90m',
        '1' : '\033[0;31m',
        '2' : '\033[0;32m',
        '3' : '\033[0;33m',
        '4' : '\033[0;34m',
        '5' : '\033[0;36m',
        '6' : '\033[0;35m',
        '7' : '\033[0;37m',
        '8' : '\033[0;41m',
        }

ARENA_HTML_COLORS = {
        '0' : '000000',
        '1' : 'ff0000',
        '2' : '00ff00',
        '3' : 'ffff00',
        '4' : '0000ff',
        '5' : '00ffff',
        '6' : 'ff00ff',
        '7' : 'ffffff',
        '8' : 'ff6d00',
        }

CHALLENGE_BYTES = 8

CONNECTIONLESS_PREFIX = b"\xff\xff\xff\xff"
RESPONSE_INFO   = b"infoResponse\n"
RESPONSE_STATUS = b"statusResponse\n"
MAX_MSGLEN = 16384


class ServerInfo:
    def __init__(self, ip, port, info, status, players):
        self.ip = ip
        self.port = port
        self.info = info
        self.status = status
        self.players = players

    def saddr(self):
        return "{}:{}".format(self.ip, self.port)


    def _getinfo(self, key):
        return self.info[key.lower()]

    def _getstatus(self, key):
        return self.status[key.lower()]

    def name(self):
        try:
            return ArenaString(self._getinfo(b'hostname'))
        except:
            return ArenaString(b"")

    def _getinfostr(self, key):
        try:
            return printable_string(self._getinfo(key))
        except:
            return ""

    def _getinfou(self, key):
        try:
            n = int(self._getinfo(key))
            return n if n >= 0 else 0
        except:
            return 0

    def map(self):
        return self._getinfostr(b'mapname')

    def game(self):
        return self._getinfostr(b'game')

    def gametypenum(self):
        return self._getinfou(b'gametype')

    def gametype(self):
        try:
            gtn = int(self._getinfo(b'gametype'))
            return Gametype(gtn)
        except (ValueError, KeyError):
            return Gametype.UNKNOWN;

    def num_humans(self):
        return self._getinfou(b'g_humanplayers')

    def num_clients(self):
        return self._getinfou(b'clients')

    def maxclients(self):
        return self._getinfou(b'sv_maxclients')

    def all_players(self):
        return self.players

    def likely_human_players(self):
        expected = self.num_humans()
        players = [p for p in self.players if p.likely_human()]
        if len(players) < expected:
            return self.all_players()
        return players

def printable_string(s):
    s = s.decode(encoding='ascii', errors='replace')
    return ''.join((c if c.isprintable() else '\uFFFD' for c in s))

ARENA_CHARMAP = "⏺◢▬◣▌\uFFFD▐◥▀◤▁█\uFFFD▶\uFFFD\uFFFD[]┏━┓▌\uFFFD▐┗━┛\uFFFD┘◄━►"

def _arena_printable_char(c):
    if ord(c) < len(ARENA_CHARMAP):
        c = ARENA_CHARMAP[ord(c)]
    if c.isprintable():
        return c
    return '\uFFFD'

def _arena_printable_string(s):
    s = s.decode(encoding='ascii', errors='replace')
    return ''.join((_arena_printable_char(c) for c in s))

def termcolor(match):
    try:
        return ARENA_COLORS[match.group(0).lstrip('^')]
    except:
        return match.group(0)


def _html_fonttag(color):
    return '<font color="#{}">'.format(color)

class ArenaString:
    def __init__(self, s):
        self.s = _arena_printable_string(s)

    def strip(self):
        stripped = ArenaString(b"")
        stripped.s = self.s.strip()
        return stripped

    def getstr(self, color=False):
        pat = "\^[0-8]"
        if color:
            return ARENA_COLORS['7'] + re.sub(pat, termcolor, self.s) + COLOR_RESET
        return re.sub(pat, "", self.s)

    def gethtml(self):
        res = []
        pat = "\^[0-8]"
        lastidx = 0
        res.append(_html_fonttag(ARENA_HTML_COLORS['7']))
        for match in re.finditer(pat, self.s):
            cs = match.group(0).lstrip('^')
            if cs not in ARENA_HTML_COLORS:
                continue
            p = self.s[lastidx:match.start()]
            res.append(html.escape(p))
            lastidx = match.end()
            res.append('</font>')
            res.append(_html_fonttag(ARENA_HTML_COLORS[cs]))
        p = self.s[lastidx:]
        res.append(html.escape(p))
        res.append('</font>')
        return ''.join(res)

class Player:
    def __init__(self, name, score=0, ping=0):
        self.name = ArenaString(name)
        self.score = score
        self.ping = ping

    def likely_human(self):
        return self.ping != 0

def player_from_str(s):
    try:
        fields = s.split(b" ", maxsplit=2)
        score = int(fields[0])
        ping = int(fields[1])
        name = fields[2][1:-1]
        return Player(name, score, ping)
    except:
        return None

@enum.unique
class Gametype(enum.Enum):
    FFA             = 0
    TOURNAMENT      = 1
    SINGLE_PLAYER   = 2
    TEAM            = 3
    CTF             = 4
    ONEFCTF         = 5
    OBELISK         = 6
    HARVESTER       = 7
    ELIMINATION     = 8
    CTF_ELIMINATION = 9
    LMS             = 10
    DOUBLE_D        = 11
    DOMINATION      = 12
    TREASURE_HUNTER = 13
    MULTITOURNAMENT = 14
    UNKNOWN         = -1

    def __str__(self):
        if self == Gametype.FFA:
            return "Free For All";
        if self == Gametype.SINGLE_PLAYER:
            return "Single Player";
        if self == Gametype.TOURNAMENT:
            return "Tournament";
        if self == Gametype.TEAM:
            return "Team Deathmatch";
        if self == Gametype.CTF:
            return "Capture The Flag";
        if self == Gametype.ONEFCTF:
            return "One Flag CTF";
        if self == Gametype.OBELISK:
            return "Overload";
        if self == Gametype.HARVESTER:
            return "Harvester";
        if self == Gametype.ELIMINATION:
            return "Elimination";
        if self == Gametype.CTF_ELIMINATION:
            return "CTF Elimination";
        if self == Gametype.LMS:
            return "Last Man Standing";
        if self == Gametype.DOUBLE_D:
            return "Double Domination";
        if self == Gametype.DOMINATION:
            return "Domination";
        if self == Gametype.TREASURE_HUNTER:
            return "Treasure Hunter";
        if self == Gametype.MULTITOURNAMENT:
            return "Multitournament";

        return "Unknown Gametype";

class QueryDispatcher:
    def __init__(self, socket):
        self.queries = {}
        self._socket = socket

    def insert(self, query):
        self.queries[query.addr()] = query

    def getinfo(self):
        for query in self.queries.values():
            query.send_getinfo(self._socket)

    def getstatus(self):
        for query in self.queries.values():
            query.send_getstatus(self._socket)

    def pending(self):
        return any((q.pending() for q in self.queries.values()))

    def retry(self):
        for query in self.queries.values():
            query.retry(self._socket)

    def recv(self, timeout=RESPONSE_TIMEOUT):
        late = time.time() + timeout
        while self.pending():
            timeout = late - time.time()
            if timeout <= 0:
                print("Warning: timed out waiting for response(s)", file=sys.stderr)
                return False
            (r, _, _) = select.select([self._socket], [], [], timeout)
            if not len(r):
                continue
            try:
                (data, raddr) = self._socket.recvfrom(MAX_MSGLEN, socket.MSG_DONTWAIT)
            except BlockingIOError as e:
                continue
            except OSError as e:
                print("Socket error: {}".format(e), file=sys.stderr)
                continue

            if raddr not in self.queries:
                continue

            try:
                self.queries[raddr].parse_response(data)
            except ArenaError as e:
                print("Error when parsing packet from {}: {}".format(raddr, e), file=sys.stderr)
        return True

    def collect(self):
        l = [q.build_info() for q in self.queries.values()]
        return [info for info in l if info]


def _parse_infostring(s):
    delim = b'\\'
    if s.startswith(delim):
        s = s[len(delim):]
    tokens = s.split(delim)
    return dict(
            zip((k.lower() for k in itertools.islice(tokens,0,None,2)),
                itertools.islice(tokens,1,None,2))
            )

def _generate_challenge(sz=CHALLENGE_BYTES):
    return secrets.token_hex(sz).encode()

class ServerQuery:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

        self._info = None
        self._statusinfo = None
        self._players = None

        self.reset()

    def build_info(self):
        if (self._info is None
                or self._statusinfo is None
                or self._players is None):
            return None
        return ServerInfo(self.ip, self.port, self._info, self._statusinfo, self._players)

    def reset(self):
        self._challenge_info = None
        self._challenge_status = None

    def pending_info(self):
        return self._challenge_info is not None

    def pending_status(self):
        return self._challenge_status is not None

    def pending(self):
        return self.pending_info() or self.pending_status()

    def addr(self):
        return (self.ip, self.port)

    def _send_request(self, request, sock):
        sock.sendto(CONNECTIONLESS_PREFIX + request, (self.ip, self.port))

    def send_getinfo(self, sock):
        if not self._challenge_info:
            self._challenge_info = _generate_challenge()
        request = b"".join((b"getinfo ", self._challenge_info, b"\n"))
        self._send_request(request, sock)

    def send_getstatus(self, sock):
        if not self._challenge_status:
            self._challenge_status = _generate_challenge()
        request = b"".join((b"getstatus ", self._challenge_status, b"\n"))
        self._send_request(request, sock)

    def retry(self, sock):
        if self.pending_info():
            self.send_getinfo(sock)
        if self.pending_status():
            self.send_getstatus(sock)

    def parse_response(self, data):
        if not data.startswith(CONNECTIONLESS_PREFIX):
            raise ArenaError("invalid connectionless packet packet")

        data = data[len(CONNECTIONLESS_PREFIX):]

        if data.lower().startswith(RESPONSE_INFO.lower()):
            return self._parse_inforesponse(data[len(RESPONSE_INFO):])
        elif data.lower().startswith(RESPONSE_STATUS.lower()):
            return self._parse_statusresponse(data[len(RESPONSE_STATUS):])

        raise ArenaError("unknown packet type")

    def _parse_inforesponse(self, data):
        info = _parse_infostring(data)
        if b"challenge" not in info or info[b"challenge"] != self._challenge_info:
            raise ArenaError("invalid challenge")
        del info[b'challenge']
        self._info = info
        self._challenge_info = None

    def _parse_statusresponse(self, data):
        lines = data.split(b"\n")
        if len(lines) < 2:
            raise ArenaError("invalid status response format")
        info = _parse_infostring(lines[0])
        if b"challenge" not in info or info[b"challenge"] != self._challenge_status:
            raise ArenaError("invalid challenge")
        del info[b'challenge']
        self._statusinfo = info
        self._challenge_status = None
        self._players = [p for p in [player_from_str(s) for s in lines[1:-1]] if p]

class ArenaError(Exception):
    def __init__(self, message):
        self.message = message

def query_servers(addrs, timeout=RESPONSE_TIMEOUT, retries=QUERY_RETRIES):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    dispatcher = QueryDispatcher(sock)
    for (ip, port) in addrs:
        dispatcher.insert(ServerQuery(ip, port))

    dispatcher.getinfo()
    dispatcher.getstatus()
    while not dispatcher.recv(timeout) and retries > 0:
        retries -= 1
        dispatcher.retry()

    for query in dispatcher.queries.values():
        if query.pending_info():
            print("Warning: did not receive a valid info response from {}".format(query.addr()), file=sys.stderr)
        if query.pending_status():
            print("Warning: did not receive a valid status response from {}".format(query.addr()), file=sys.stderr)

    return dispatcher.collect()

def pretty_print(serverinfos, show_empty=False, colors=False, bots=False, sort=False):
    if sort:
        serverinfos = sorted(serverinfos, key=lambda x: x.num_humans(), reverse=True)
    for info in serverinfos:
        if not (show_empty or info.num_humans()):
            continue
        just = 21
        fields = []
        fields.append(info.saddr().rjust(just))
        fields.append(info.name().strip().getstr(colors))

        print(' '.join(fields))
        fields = []
        fields.append('Map:'.rjust(just))
        fields.append(info.map())
        print(' '.join(fields))

        fields = []
        fields.append('Players:'.rjust(just))
        nplayers = info.num_humans()
        maxclients = info.maxclients()
        cformat = ""
        creset = ""
        if (colors):
            creset = COLOR_RESET
            if nplayers >= maxclients:
                cformat = ARENA_COLORS['1']
            elif nplayers >= maxclients/4 * 3:
                cformat = ARENA_COLORS['3']
            elif nplayers > 0:
                cformat = ARENA_COLORS['2']

        fields.append('{}{}/{}{}'.format(cformat, nplayers, maxclients, creset))
        print(' '.join(fields))
        players = info.all_players() if bots else info.likely_human_players()
        if sort:
            players = sorted(players, key=lambda p: p.score, reverse=True)
        for p in players:
            fields = []
            fields.append(''.rjust(just))
            fields.append("{:4}".format(p.score))
            fields.append("{:4}ms".format(p.ping))
            fields.append(p.name.getstr(colors))
            print(' '.join(fields))




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Query OpenArena servers.')
    parser.add_argument('servers', metavar='HOST:PORT', nargs='+', help='servers to query')
    parser.add_argument('--no-colors', action='store_true', help='disable color output')
    parser.add_argument('--colors', action='store_true', help='force color output')
    parser.add_argument('--empty', action='store_true', help='show empty servers')
    parser.add_argument('--bots', action='store_true', help='show bots')
    parser.add_argument('--sort', action='store_true', help='enable sorting')
    parser.add_argument('--timeout', metavar='SECONDS', type=float, default=RESPONSE_TIMEOUT, help='timeout, in seconds')
    parser.add_argument('--retries', type=int, default=QUERY_RETRIES, help='number of retries')
    args = parser.parse_args()

    addrs = []
    for srv in args.servers:
        try:
            l = srv.split(':')
            raddr = (socket.gethostbyname(l[0]), int(l[1]))
            addrs.append(raddr)
        except socket.gaierror as e:
            print("Failed to resolve host: {}".format(e), file=sys.stderr)
            sys.exit(2)
        except:
            print("invalid server address {}".format(srv), file=sys.stderr)
            sys.exit(1)

    if args.timeout <= 0:
        print("invalid timeout {}".format(args.timeout), file=sys.stderr)
        sys.exit(1)

    if args.retries < 0:
        print("invalid retries {}".format(args.retries), file=sys.stderr)
        sys.exit(1)

    server_infos =  query_servers(addrs, args.timeout, args.retries)

    colors = not args.no_colors and (args.colors or sys.stdout.isatty())
    pretty_print(server_infos, args.empty, colors, args.bots, args.sort)
    sys.exit(0)

